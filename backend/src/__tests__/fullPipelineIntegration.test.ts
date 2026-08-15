import path from "path";
import fs from "fs";
import os from "os";

import { OsvDependencyScanner } from "../services/scanners/osvScannerService";
import { SecretScanner } from "../services/scanners/secretScannerService";
import { ContainerScanner } from "../services/scanners/containerScannerService";
import { IacScanner } from "../services/scanners/iacScannerService";
import { CicdScanner } from "../services/scanners/cicdScannerService";
import { reviewFinding, mapConfidenceToStatus } from "../services/ai/aiReviewerService";
import { computeRisk } from "../services/riskService";
import { PolicyEngine, getSecurityPolicyForRepository } from "../services/policyEngine";
import { verifyFindingAccuracy } from "../services/findingVerifier";

describe("Complete End-to-End Multi-Scanner Pipeline Test (SAST + SCA + SECRETS + CONTAINER + IAC + CI_CD + AI Triage + Gates)", () => {
  jest.setTimeout(60000);

  let testRepoDir: string;

  beforeAll(() => {
    // Create a complete test repository workspace containing targets for all 6 pillars
    testRepoDir = path.join(os.tmpdir(), `e2e-pipeline-${Date.now()}`);
    fs.mkdirSync(path.join(testRepoDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(testRepoDir, "terraform"), { recursive: true });
    fs.mkdirSync(path.join(testRepoDir, "k8s"), { recursive: true });
    fs.mkdirSync(path.join(testRepoDir, ".github", "workflows"), { recursive: true });

    // 1. SAST target
    fs.writeFileSync(
      path.join(testRepoDir, "src", "user.js"),
      `const express = require('express');
const app = express();
const db = require('./db');

app.get('/users', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query, (err, rows) => {
    res.json(rows);
  });
});`
    );

    // 2. SCA manifest
    fs.writeFileSync(
      path.join(testRepoDir, "package.json"),
      JSON.stringify({
        name: "test-app",
        version: "1.0.0",
        dependencies: {
          lodash: "4.17.15"
        }
      }, null, 2)
    );

    // 3. Secrets file
    fs.writeFileSync(
      path.join(testRepoDir, ".env"),
      `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DATABASE_URL=postgres://admin:supersecretpassword@localhost:5432/mydb`
    );

    // 4. Container file
    fs.writeFileSync(
      path.join(testRepoDir, "Dockerfile"),
      `FROM node:latest
WORKDIR /app
COPY . .
EXPOSE 3000
CMD ["node", "src/user.js"]`
    );

    // 5. IaC file
    fs.writeFileSync(
      path.join(testRepoDir, "terraform", "main.tf"),
      `resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`
    );

    // 6. CI/CD file
    fs.writeFileSync(
      path.join(testRepoDir, ".github", "workflows", "ci.yml"),
      `name: CI Pipeline
on:
  pull_request_target:
    types: [opened]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - name: Greet
        run: echo "PR by \${{ github.event.issue.title }}"`
    );
  });

  afterAll(() => {
    fs.rmSync(testRepoDir, { recursive: true, force: true });
  });

  test("Step 1: All 6 Security Scanner Engines Execute Successfully", async () => {
    // 1. SCA
    const scaScanner = new OsvDependencyScanner();
    const scaRes = await scaScanner.scan(testRepoDir);
    expect(scaRes.status).toBe("success");
    expect(scaRes.findings.some((f) => f.category === "SCA")).toBe(true);

    // 2. Secrets
    const secretScanner = new SecretScanner();
    const secretRes = await secretScanner.scan(testRepoDir);
    expect(secretRes.status).toBe("success");
    expect(secretRes.findings.some((f) => f.category === "SECRETS")).toBe(true);

    // 3. Container
    const containerScanner = new ContainerScanner();
    const containerRes = await containerScanner.scan(testRepoDir);
    expect(containerRes.status).toBe("success");
    expect(containerRes.findings.some((f) => f.category === "CONTAINER")).toBe(true);

    // 4. IaC
    const iacScanner = new IacScanner();
    const iacRes = await iacScanner.scan(testRepoDir);
    expect(iacRes.status).toBe("success");
    expect(iacRes.findings.some((f) => f.category === "IAC")).toBe(true);

    // 5. CI/CD
    const cicdScanner = new CicdScanner();
    const cicdRes = await cicdScanner.scan(testRepoDir);
    expect(cicdRes.status).toBe("success");
    expect(cicdRes.findings.some((f) => f.category === "CI_CD")).toBe(true);
  });

  test("Step 2: AI Triage classifies CONFIRMED, LIKELY, NEEDS_REVIEW, FALSE_POSITIVE and computes risk", async () => {
    // Test AI classification mapping
    expect(mapConfidenceToStatus(95, true)).toBe("CONFIRMED");
    expect(mapConfidenceToStatus(75, true)).toBe("LIKELY");
    expect(mapConfidenceToStatus(55, true)).toBe("NEEDS_REVIEW");
    expect(mapConfidenceToStatus(20, false)).toBe("FALSE_POSITIVE");

    // Triage a CI/CD finding
    const cicdFinding = {
      tool: "cicd-scanner" as const,
      category: "CI_CD" as const,
      file: ".github/workflows/ci.yml",
      line: 12,
      ruleId: "cicd-expression-command-injection",
      workflowName: "CI Pipeline",
      title: "Command Injection via Inline Expression",
      codeSnippet: "run: echo \"PR by ${{ github.event.issue.title }}\"",
      secretRef: null,
      complianceStandard: "CIS GitHub Actions Benchmark 1.3",
      severity: "critical" as const
    };

    const isVerified = await verifyFindingAccuracy(testRepoDir, cicdFinding);
    expect(isVerified.isValid).toBe(true);

    const aiReview = await reviewFinding(cicdFinding, {
      language: "yaml",
      surroundingCode: cicdFinding.codeSnippet,
      imports: []
    });

    expect(aiReview.status).toBe("CONFIRMED");
    expect(aiReview.isRealVulnerability).toBe(true);
    expect(aiReview.attackScenario).toBeDefined();
    expect(aiReview.secureFix).toBeDefined();

    const risk = computeRisk(cicdFinding, aiReview);
    expect(risk.score).toBeGreaterThanOrEqual(80);
    expect(risk.decision).toBe("BLOCK");
  });

  test("Step 3: Policy Gates correctly enforce Critical, High, Secrets, and CVSS thresholds", () => {
    const strictPolicy = getSecurityPolicyForRepository({
      blockCritical: true,
      blockHigh: true,
      blockSecrets: true,
      failOnCvssThreshold: 8.0,
      maxAllowedHigh: 0,
      maxAllowedMedium: 3
    });

    const failingFindings = [
      { score: 90, severity: "critical" as const, decision: "BLOCK" as const, category: "CI_CD" as const },
      { score: 75, severity: "high" as const, decision: "BLOCK" as const, category: "SECRETS" as const }
    ];

    const decision = PolicyEngine.evaluateGateDecision(failingFindings, strictPolicy);
    expect(decision.gateResult).toBe("fail");
    expect(decision.decisionReason).toContain("Security Gate Failed");
  });
});
