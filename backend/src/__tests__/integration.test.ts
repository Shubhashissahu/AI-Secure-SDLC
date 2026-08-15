import path from "path";
import { SemgrepScanner } from "../services/scanners/semgrepService";
import { computeRisk } from "../services/riskService";
import { PolicyEngine, DEFAULT_SECURITY_POLICY } from "../services/policyEngine";
import { SarifService } from "../services/sarifService";
import { AiReviewResult } from "../services/ai/aiReviewerService";

describe("End-to-End DevSecOps Integration Pipeline Test", () => {
  jest.setTimeout(30000);
  const securityTestAppPath = path.join(__dirname, "../../../security-test-app");

  test("runs real Semgrep scanner against security-test-app, detects Java SQL Injection, and enforces CI failure", async () => {
    // 1. Real Scanner Execution
    const semgrepScanner = new SemgrepScanner();
    const semgrepRes = await semgrepScanner.scan(securityTestAppPath);

    expect(semgrepRes.status).toBe("success");
    expect(semgrepRes.findings.length).toBeGreaterThan(0);

    // Verify Java SQL Injection is detected
    const sqliFinding = semgrepRes.findings.find(
      (f) => f.ruleId.includes("sql-injection") || f.ruleId.includes("sqli")
    );

    expect(sqliFinding).toBeDefined();
    expect(sqliFinding?.tool).toBe("semgrep");
    expect(sqliFinding?.file.replace(/\\/g, "/")).toContain("login.java");
    expect(sqliFinding?.cwe).toBe("CWE-89");
    expect(["high", "critical"]).toContain(sqliFinding?.severity);

    // 2. AI Review & Multi-Factor Risk Calculation
    const mockReview: AiReviewResult = {
      isRealVulnerability: true,
      confidence: 95,
      confidenceLevel: "allow_automated_decision",
      severity: "CRITICAL",
      status: "CONFIRMED",
      reason: "SQL injection identified in login data flow",
      attackScenario: "Attacker supplies malicious SQL payload in request parameters.",
      cwe: "CWE-89",
      owasp: "A03:2021 - Injection",
      exploitability: "high",
      recommendation: "Use PreparedStatement parameterized queries.",
      secureFix: "PreparedStatement stmt = conn.prepareStatement(query);",
      reviewFailed: false
    };

    const risk = computeRisk(sqliFinding!, mockReview, DEFAULT_SECURITY_POLICY);
    expect(risk.score).toBeGreaterThanOrEqual(60);
    expect(risk.decision).toBe("BLOCK");

    // 3. Security Policy Gate Decision
    const evaluatedFindings = [{
      score: risk.score,
      severity: sqliFinding!.severity,
      decision: risk.decision
    }];

    const gateResult = PolicyEngine.evaluateGateDecision(evaluatedFindings, DEFAULT_SECURITY_POLICY);
    expect(gateResult.gateResult).toBe("fail");

    // 4. SARIF Generation
    const mockScan = { _id: "66b3f912e8b0a1d48c8f0011", startedAt: new Date(), gateResult: gateResult.gateResult } as any;
    const sarifLog = SarifService.generateSarif(mockScan, [
      {
        ...sqliFinding,
        ai: mockReview,
        risk
      } as any
    ]);

    expect(sarifLog.version).toBe("2.1.0");
    expect(sarifLog.runs[0].tool.driver.name).toBe("ai-secure-sdlc-platform");
  }, 30000);
});

