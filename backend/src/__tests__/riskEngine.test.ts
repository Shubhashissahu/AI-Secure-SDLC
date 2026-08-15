import { computeRisk } from "../services/riskService";
import { NormalizedFinding } from "../services/scanners/types";
import { AiReviewResult } from "../services/ai/aiReviewerService";

describe("RiskEngine Unit Tests", () => {
  const sampleFinding: NormalizedFinding = {
    tool: "semgrep",
    file: "src/controllers/authController.js",
    line: 42,
    ruleId: "sqli-concat",
    codeSnippet: "db.query('SELECT * FROM users WHERE id = ' + userId);",
    secretRef: null,
    severity: "high"
  };

  const sampleReview: AiReviewResult = {
    isRealVulnerability: true,
    confidence: 90,
    confidenceLevel: "allow_automated_decision",
    severity: "CRITICAL",
    status: "CONFIRMED",
    reason: "SQL injection in auth controller",
    attackScenario: "Attacker supplies SQL injection payload.",
    cwe: "CWE-89",
    owasp: "A03:2021-Injection",
    exploitability: "high",
    recommendation: "Use parameterized query.",
    secureFix: "db.query('SELECT * FROM users WHERE id = ?', [userId]);",
    reviewFailed: false
  };

  test("computes high risk score for confirmed high vulnerability in sensitive auth controller without false escalation to critical", () => {
    const risk = computeRisk(sampleFinding, sampleReview);
    expect(risk.score).toBeGreaterThanOrEqual(65);
    expect(risk.score).toBeLessThanOrEqual(84);
    expect(risk.severity).toBe("HIGH");
    expect(risk.decision).toBe("BLOCK");
  });

  test("computes critical risk score for confirmed critical vulnerability", () => {
    const criticalFinding: NormalizedFinding = { ...sampleFinding, severity: "critical" };
    const risk = computeRisk(criticalFinding, sampleReview);
    expect(risk.score).toBeGreaterThanOrEqual(85);
    expect(risk.severity).toBe("CRITICAL");
    expect(risk.decision).toBe("BLOCK");
  });


  test("zeroes out risk score for false positive findings", () => {
    const falsePositiveReview: AiReviewResult = {
      ...sampleReview,
      isRealVulnerability: false
    };

    const risk = computeRisk(sampleFinding, falsePositiveReview);
    expect(risk.score).toBe(0);
    expect(risk.decision).toBe("IGNORE");
  });
});
