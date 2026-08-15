import { PolicyEngine, SecurityPolicy } from "../services/policyEngine";

describe("PolicyEngine Unit Tests", () => {
  const customPolicy: SecurityPolicy = {
    critical: { action: "BLOCK" },
    high: { action: "BLOCK" },
    medium: { action: "WARN" },
    low: { action: "IGNORE" },
    maxAllowedHigh: 0,
    maxAllowedMedium: 2
  };

  test("evaluates individual finding actions correctly", () => {
    expect(PolicyEngine.evaluateFindingAction("critical", customPolicy)).toBe("BLOCK");
    expect(PolicyEngine.evaluateFindingAction("medium", customPolicy)).toBe("WARN");
    expect(PolicyEngine.evaluateFindingAction("low", customPolicy)).toBe("IGNORE");
  });

  test("fails gate decision when a finding triggers a BLOCK action", () => {
    const findings = [
      { score: 85, severity: "critical" as const, decision: "BLOCK" as const }
    ];

    const result = PolicyEngine.evaluateGateDecision(findings, customPolicy);
    expect(result.gateResult).toBe("fail");
    expect(result.decisionReason).toContain("Security Gate Failed");
  });

  test("passes gate decision when all findings are WARN or IGNORE", () => {
    const findings = [
      { score: 35, severity: "medium" as const, decision: "WARN" as const }
    ];

    const result = PolicyEngine.evaluateGateDecision(findings, customPolicy);
    expect(result.gateResult).toBe("pass");
  });
});
