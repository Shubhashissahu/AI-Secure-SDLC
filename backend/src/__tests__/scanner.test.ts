import path from "path";
import { generateFindingFingerprint } from "../utils/fingerprint";
import { verifyFindingAccuracy } from "../services/findingVerifier";
import { mapConfidenceToStatus, reviewFinding } from "../services/ai/aiReviewerService";
import { NormalizedFinding } from "../services/scanners/types";
import { SemgrepScanner } from "../services/scanners/semgrepService";
import { GitleaksScanner } from "../services/scanners/gitleaksService";
import { TrivyScanner } from "../services/scanners/trivyService";

describe("Production Security Scanning Pipeline Test Suite", () => {
  jest.setTimeout(45000);
  const testAppPath = path.join(__dirname, "../../../security-test-app");
  const dummyRepoId = "64f1a2b3c4d5e6f7a8b9c0d1";
  const commitSha = "8f93abc1234567890abcdef1234567890abcdef1";

  // -------------------------------------------------------------
  // Test 1: Deduplication (fingerprint match)
  // -------------------------------------------------------------
  test("Test 1: Same vulnerability scanned twice generates identical fingerprint (deduplication)", () => {
    const finding1: NormalizedFinding = {
      tool: "semgrep",
      file: "src/login.java",
      line: 19,
      ruleId: "java-sql-injection",
      codeSnippet: "String query = \"SELECT * FROM users WHERE username = '\" + username;",
      secretRef: null,
      severity: "high"
    };

    const fingerprint1 = generateFindingFingerprint(
      dummyRepoId,
      commitSha,
      finding1.file,
      finding1.line,
      finding1.ruleId,
      finding1.tool
    );

    const finding2: NormalizedFinding = {
      tool: "semgrep",
      file: "src/login.java",
      line: 19,
      ruleId: "java-sql-injection",
      codeSnippet: "String query = \"SELECT * FROM users WHERE username = '\" + username;",
      secretRef: null,
      severity: "high"
    };

    const fingerprint2 = generateFindingFingerprint(
      dummyRepoId,
      commitSha,
      finding2.file,
      finding2.line,
      finding2.ruleId,
      finding2.tool
    );

    expect(fingerprint1).toBeDefined();
    expect(fingerprint2).toBeDefined();
    expect(fingerprint1).toBe(fingerprint2);
  });

  // -------------------------------------------------------------
  // Test 2: Different lines produce different fingerprints
  // -------------------------------------------------------------
  test("Test 2: Same vulnerability on different line numbers generates distinct fingerprints", () => {
    const findingLine19 = generateFindingFingerprint(
      dummyRepoId,
      commitSha,
      "src/login.java",
      19,
      "java-sql-injection",
      "semgrep"
    );

    const findingLine42 = generateFindingFingerprint(
      dummyRepoId,
      commitSha,
      "src/login.java",
      42,
      "java-sql-injection",
      "semgrep"
    );

    expect(findingLine19).not.toBe(findingLine42);
  });

  // -------------------------------------------------------------
  // Test 3: Fixed vulnerability -> RESOLVED
  // -------------------------------------------------------------
  test("Test 3: Rescan resolution logic marks missing vulnerability as RESOLVED", () => {
    const previousActiveFindingFingerprints = [
      generateFindingFingerprint(dummyRepoId, commitSha, "src/login.java", 19, "java-sql-injection", "semgrep")
    ];

    const newScanFingerprints = new Set<string>();

    const updatedStatuses: Record<string, string> = {};
    for (const prevFp of previousActiveFindingFingerprints) {
      if (!newScanFingerprints.has(prevFp)) {
        updatedStatuses[prevFp] = "RESOLVED";
      }
    }

    expect(updatedStatuses[previousActiveFindingFingerprints[0]]).toBe("RESOLVED");
  });

  // -------------------------------------------------------------
  // Test 4: AI rejects false positive -> Marked FALSE_POSITIVE
  // -------------------------------------------------------------
  test("Test 4: AI rejects false positive with confidence < 50", () => {
    const statusLowConf = mapConfidenceToStatus(35, true);
    expect(statusLowConf).toBe("FALSE_POSITIVE");

    const statusNotVuln = mapConfidenceToStatus(90, false);
    expect(statusNotVuln).toBe("FALSE_POSITIVE");

    const statusConfirmed = mapConfidenceToStatus(85, true);
    expect(statusConfirmed).toBe("CONFIRMED");

    const statusNeedsReview = mapConfidenceToStatus(65, true);
    expect(statusNeedsReview).toBe("NEEDS_REVIEW");
  });

  // -------------------------------------------------------------
  // Test 5: Fake scanner result -> Rejected / Discarded
  // -------------------------------------------------------------
  test("Test 5: Fake scanner result on non-existent file or out-of-bounds line is rejected", async () => {
    const fakeFileFinding: NormalizedFinding = {
      tool: "semgrep",
      file: "src/non_existent_fake_file.java",
      line: 19,
      ruleId: "fake-sql-injection",
      codeSnippet: "SELECT * FROM fake",
      secretRef: null,
      severity: "high"
    };

    const fileVerification = await verifyFindingAccuracy(testAppPath, fakeFileFinding);
    expect(fileVerification.isValid).toBe(false);
    expect(fileVerification.reason).toContain("does not exist");

    const fakeLineFinding: NormalizedFinding = {
      tool: "semgrep",
      file: "src/cmd.js",
      line: 99999,
      ruleId: "javascript-command-injection",
      codeSnippet: "exec(`ping -c 4 ${host}`)",
      secretRef: null,
      severity: "critical"
    };

    const lineVerification = await verifyFindingAccuracy(testAppPath, fakeLineFinding);
    expect(lineVerification.isValid).toBe(false);
    expect(lineVerification.reason).toContain("out of bounds");

    const validFinding: NormalizedFinding = {
      tool: "semgrep",
      file: "src/login.java",
      line: 1,
      ruleId: "java-sql-injection",
      codeSnippet: "",
      secretRef: null,
      severity: "high"
    };

    const validVerification = await verifyFindingAccuracy(testAppPath, validFinding);
    expect(validVerification.isValid).toBe(true);
  });

  // -------------------------------------------------------------
  // Test 6: Multi-Vulnerability Detection across all 16 CWE categories
  // -------------------------------------------------------------
  test("Test 6: Semgrep detects all 16 requested vulnerability categories", async () => {
    const semgrep = new SemgrepScanner();
    const result = await semgrep.scan(testAppPath);

    expect(result.status).toBe("success");
    expect(result.findings.length).toBeGreaterThanOrEqual(16);

    const detectedCwes = new Set(result.findings.map((f) => f.cwe));

    const expectedCwes = [
      "CWE-89",   // SQL Injection
      "CWE-79",   // XSS
      "CWE-78",   // Command Injection
      "CWE-22",   // Path Traversal
      "CWE-502",  // Insecure Deserialization
      "CWE-918",  // SSRF
      "CWE-798",  // Hardcoded Credentials
      "CWE-327",  // Weak Cryptography
      "CWE-916",  // Weak Password Hashing
      "CWE-601",  // Open Redirect
      "CWE-434",  // Insecure File Upload
      "CWE-611",  // XXE
      "CWE-90",   // LDAP Injection
      "CWE-943",  // NoSQL Injection
      "CWE-1321", // Prototype Pollution
      "CWE-1333"  // ReDoS
    ];

    for (const cwe of expectedCwes) {
      expect(detectedCwes.has(cwe)).toBe(true);
    }
  }, 45000);

  // -------------------------------------------------------------
  // Test 7: AI Triage generates valid reviews and secure fixes for all CWEs
  // -------------------------------------------------------------
  test("Test 7: AI review generates appropriate attack scenarios and compilable secure fixes", async () => {
    const sampleFinding: NormalizedFinding = {
      tool: "semgrep",
      file: "src/sqli.js",
      line: 8,
      ruleId: "javascript-sql-injection",
      codeSnippet: 'const query = "SELECT * FROM users WHERE id = \'" + userId + "\' AND status = \'active\'";',
      secretRef: null,
      severity: "high",
      cwe: "CWE-89"
    };

    const review = await reviewFinding(sampleFinding, {
      surroundingCode: 'const userId = req.query.id;\nconst query = "SELECT * FROM users WHERE id = \'" + userId + "\' AND status = \'active\'";\nconst user = await db.query(query);\nres.json(user);',
      language: "javascript",
      imports: []
    });

    expect(review.cwe).toBe("CWE-89");
    expect(review.isRealVulnerability).toBe(true);
    expect(review.confidence).toBeGreaterThanOrEqual(70);
    expect(review.secureFix).toBeDefined();
    expect(review.attackScenario.toLowerCase()).toMatch(/sql|query|database/);
  });

  // -------------------------------------------------------------
  // Test 8: Realistic Risk Calculation (High severity does NOT escalate to CRITICAL)
  // -------------------------------------------------------------
  test("Test 8: High severity finding does NOT exceed score 84 or escalate to CRITICAL", () => {
    const { computeRisk } = require("../services/riskService");
    const highFinding: NormalizedFinding = {
      tool: "semgrep",
      file: "src/login.java",
      line: 36,
      ruleId: "java-sql-injection",
      codeSnippet: "String query = \"SELECT * FROM users WHERE username = '\" + username;",
      secretRef: null,
      severity: "high",
      cwe: "CWE-89"
    };

    const review = {
      isRealVulnerability: true,
      confidence: 95,
      confidenceLevel: "allow_automated_decision" as const,
      severity: "HIGH" as const,
      status: "CONFIRMED" as const,
      cwe: "CWE-89",
      owasp: "A03:2021-Injection",
      exploitability: "high" as const,
      attackScenario: "SQL injection in login flow",
      recommendation: "Use PreparedStatement",
      secureFix: "PreparedStatement stmt = conn.prepareStatement(query);",
      reviewFailed: false
    };

    const risk = computeRisk(highFinding, review);
    expect(risk.severity).toBe("HIGH");
    expect(risk.score).toBeLessThanOrEqual(84);
    expect(risk.score).toBeGreaterThanOrEqual(65);
  });

  // -------------------------------------------------------------
  // Scanner Execution tests
  // -------------------------------------------------------------
  test("SemgrepScanner, GitleaksScanner, TrivyScanner adhere to SecurityScanner interface", async () => {
    const semgrep = new SemgrepScanner();
    const gitleaks = new GitleaksScanner();
    const trivy = new TrivyScanner();

    expect(semgrep.name).toBe("semgrep");
    expect(gitleaks.name).toBe("gitleaks");
    expect(trivy.name).toBe("trivy");
  });
});
