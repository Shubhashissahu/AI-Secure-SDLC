import { CicdScanner } from "../services/scanners/cicdScannerService";
import { PolicyEngine, getSecurityPolicyForRepository } from "../services/policyEngine";
import { reviewFinding } from "../services/ai/aiReviewerService";
import { computeRisk } from "../services/riskService";
import { NormalizedFinding } from "../services/scanners/types";
import path from "path";
import fs from "fs";
import os from "os";

describe("CI/CD Security & Configurable Security Gates Test Suite", () => {
  jest.setTimeout(30000);

  // -------------------------------------------------------------
  // Test 1: Dangerous pull_request_target & Command Injection Detection
  // -------------------------------------------------------------
  test("Test 1: CicdScanner detects dangerous pull_request_target and command injection in .github/workflows/*.yml", async () => {
    const tmpDir = path.join(os.tmpdir(), `cicd-test-${Date.now()}`);
    const workflowsDir = path.join(tmpDir, ".github", "workflows");
    fs.mkdirSync(workflowsDir, { recursive: true });

    try {
      const dangerousWorkflow = `
name: PR Comment Processor
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - name: Process Issue Title
        run: |
          echo "Title is: \${{ github.event.issue.title }}"
          ./build.sh "\${{ github.head_ref }}"
      `;

      fs.writeFileSync(path.join(workflowsDir, "pr-check.yml"), dangerousWorkflow, "utf-8");

      const scanner = new CicdScanner();
      const result = await scanner.scan(tmpDir);

      expect(result.status).toBe("success");
      expect(result.findings.length).toBeGreaterThanOrEqual(2);

      const rules = result.findings.map((f) => f.ruleId);
      expect(rules.some((r) => r.includes("pull-request-target"))).toBe(true);
      expect(rules.some((r) => r.includes("command-injection") || r.includes("expression"))).toBe(true);

      for (const finding of result.findings) {
        expect(finding.category).toBe("CI_CD");
        expect(finding.workflowName).toBe("PR Comment Processor");
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------
  // Test 2: Secrets Exposure, Excessive Permissions, and Mutable Action Tags
  // -------------------------------------------------------------
  test("Test 2: CicdScanner detects secrets exposure in echo, write-all permissions, and mutable action tags", async () => {
    const tmpDir = path.join(os.tmpdir(), `cicd-test2-${Date.now()}`);
    const workflowsDir = path.join(tmpDir, ".github", "workflows");
    fs.mkdirSync(workflowsDir, { recursive: true });

    try {
      const insecureWorkflow = `
name: Deployment Pipeline
on: push
permissions: write-all

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v3
      - uses: third-party-unverified/custom-action@main
      - name: Deploy Production
        run: echo "Using secret: \${{ secrets.PROD_API_TOKEN }}"
      `;

      fs.writeFileSync(path.join(workflowsDir, "deploy.yaml"), insecureWorkflow, "utf-8");

      const scanner = new CicdScanner();
      const result = await scanner.scan(tmpDir);

      expect(result.status).toBe("success");
      expect(result.findings.length).toBeGreaterThanOrEqual(3);

      const rules = result.findings.map((f) => f.ruleId);
      expect(rules.some((r) => r.includes("write-all") || r.includes("permissions"))).toBe(true);
      expect(rules.some((r) => r.includes("secret") || r.includes("echo"))).toBe(true);
      expect(rules.some((r) => r.includes("mutable") || r.includes("tag"))).toBe(true);

      for (const f of result.findings) {
        expect(f.category).toBe("CI_CD");
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------
  // Test 3: Configurable Security Gates Evaluation (Critical, High, Secrets, CVSS)
  // -------------------------------------------------------------
  test("Test 3: PolicyEngine evaluates configurable security gates accurately", () => {
    // 1. Gate: FAIL if Critical > 0
    const criticalPolicy = getSecurityPolicyForRepository({
      blockCritical: true,
      blockHigh: false,
      blockSecrets: false
    });
    const criticalDecision = PolicyEngine.evaluateGateDecision(
      [
        { score: 95, severity: "critical", decision: "BLOCK" }
      ],
      criticalPolicy
    );
    expect(criticalDecision.gateResult).toBe("fail");
    expect(criticalDecision.decisionReason).toContain("Critical");

    // 2. Gate: FAIL if High > 0
    const highPolicy = getSecurityPolicyForRepository({
      blockCritical: false,
      blockHigh: true,
      maxAllowedHigh: 0
    });
    const highDecision = PolicyEngine.evaluateGateDecision(
      [
        { score: 80, severity: "high", decision: "BLOCK" }
      ],
      highPolicy
    );
    expect(highDecision.gateResult).toBe("fail");
    expect(highDecision.decisionReason).toContain("High");

    // 3. Gate: FAIL if Secrets > 0
    const secretsPolicy = getSecurityPolicyForRepository({
      blockCritical: false,
      blockHigh: false,
      blockSecrets: true
    });
    const secretsDecision = PolicyEngine.evaluateGateDecision(
      [
        { score: 70, severity: "medium", decision: "WARN", category: "SECRETS" }
      ],
      secretsPolicy
    );
    expect(secretsDecision.gateResult).toBe("fail");
    expect(secretsDecision.decisionReason).toContain("Secret");

    // 4. Gate: FAIL if CVSS >= configured threshold (e.g. threshold: 7.5, finding cvss: 8.2)
    const cvssPolicy = getSecurityPolicyForRepository({
      blockCritical: false,
      blockHigh: false,
      blockSecrets: false,
      failOnCvssThreshold: 7.5
    });
    const cvssDecision = PolicyEngine.evaluateGateDecision(
      [
        { score: 65, severity: "medium", decision: "WARN", category: "SCA", cvss: 8.2 }
      ],
      cvssPolicy
    );
    expect(cvssDecision.gateResult).toBe("fail");
    expect(cvssDecision.decisionReason).toContain("CVSS");

    // 5. Clean findings pass
    const cleanDecision = PolicyEngine.evaluateGateDecision(
      [
        { score: 20, severity: "low", decision: "IGNORE", category: "SAST", cvss: 3.1 }
      ],
      criticalPolicy
    );
    expect(cleanDecision.gateResult).toBe("pass");
  });

  // -------------------------------------------------------------
  // Test 4: AI Triage & Remediation for CI/CD Findings
  // -------------------------------------------------------------
  test("Test 4: AI Triage and secure fix generation for CI/CD pipeline findings", async () => {
    const cicdFinding: NormalizedFinding = {
      tool: "cicd-scanner",
      category: "CI_CD",
      file: ".github/workflows/deploy.yml",
      line: 12,
      ruleId: "cicd-expression-command-injection",
      workflowName: "Deploy Pipeline",
      title: "Command Injection via Inline Expression (${{ github.event.issue.title }})",
      codeSnippet: "run: echo \"${{ github.event.issue.title }}\"",
      secretRef: null,
      complianceStandard: "CIS GitHub Actions Benchmark 1.3",
      severity: "critical"
    };

    const review = await reviewFinding(cicdFinding, {
      language: "yaml",
      surroundingCode: cicdFinding.codeSnippet,
      imports: []
    });

    expect(review.status).toBe("CONFIRMED");
    expect(review.isRealVulnerability).toBe(true);
    expect(review.secureFix).toContain("env:");
    expect(review.attackScenario).toContain("GitHub Actions workflow");

    const risk = computeRisk(cicdFinding, review);
    expect(risk.score).toBeGreaterThanOrEqual(80);
    expect(risk.decision).toBe("BLOCK");
  });
});
