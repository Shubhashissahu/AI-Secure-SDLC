import { FindingSeverity } from "../models/Finding";

export type PolicyAction = "BLOCK" | "REVIEW" | "WARN" | "IGNORE";

export interface SeverityPolicyConfig {
  action: PolicyAction;
}

export interface SecurityPolicy {
  critical: SeverityPolicyConfig;
  high: SeverityPolicyConfig;
  medium: SeverityPolicyConfig;
  low: SeverityPolicyConfig;
  blockCritical?: boolean;
  blockHigh?: boolean;
  blockSecrets?: boolean;
  failOnCvssThreshold?: number;
  maxAllowedHigh?: number;
  maxAllowedMedium?: number;
}

export const DEFAULT_SECURITY_POLICY: SecurityPolicy = {
  critical: { action: "BLOCK" },
  high: { action: "BLOCK" },
  medium: { action: "WARN" },
  low: { action: "IGNORE" },
  blockCritical: true,
  blockHigh: true,
  blockSecrets: true,
  failOnCvssThreshold: 8.0,
  maxAllowedHigh: 0,
  maxAllowedMedium: 5
};

export function getSecurityPolicyForRepository(policyConfig?: {
  blockCritical?: boolean;
  blockHigh?: boolean;
  blockSecrets?: boolean;
  failOnCvssThreshold?: number;
  maxAllowedHigh?: number;
  maxAllowedMedium?: number;
}): SecurityPolicy {
  if (!policyConfig) return DEFAULT_SECURITY_POLICY;

  return {
    critical: { action: policyConfig.blockCritical !== false ? "BLOCK" : "WARN" },
    high: { action: policyConfig.blockHigh !== false ? "BLOCK" : "WARN" },
    medium: { action: "WARN" },
    low: { action: "IGNORE" },
    blockCritical: policyConfig.blockCritical !== false,
    blockHigh: policyConfig.blockHigh !== false,
    blockSecrets: policyConfig.blockSecrets !== false,
    failOnCvssThreshold: policyConfig.failOnCvssThreshold ?? 8.0,
    maxAllowedHigh: policyConfig.maxAllowedHigh ?? 0,
    maxAllowedMedium: policyConfig.maxAllowedMedium ?? 5
  };
}

export class PolicyEngine {
  /**
   * Evaluate policy action for a single finding based on severity, category, CVSS and policy configuration.
   */
  static evaluateFindingAction(
    severity: FindingSeverity,
    policy: SecurityPolicy = DEFAULT_SECURITY_POLICY,
    metadata?: { category?: string; cvss?: number }
  ): PolicyAction {
    // 1. FAIL if Secrets > 0 and blockSecrets is enabled
    if (policy.blockSecrets !== false && (metadata?.category === "SECRETS")) {
      return "BLOCK";
    }

    // 2. FAIL if CVSS >= configured threshold
    if (
      policy.failOnCvssThreshold !== undefined &&
      policy.failOnCvssThreshold > 0 &&
      metadata?.cvss !== undefined &&
      metadata.cvss >= policy.failOnCvssThreshold
    ) {
      return "BLOCK";
    }

    const normSeverity = severity.toLowerCase() as FindingSeverity;
    switch (normSeverity) {
      case "critical":
        return policy.blockCritical !== false ? (policy.critical?.action || "BLOCK") : "WARN";
      case "high":
        return policy.blockHigh !== false ? (policy.high?.action || "BLOCK") : "WARN";
      case "medium":
        return policy.medium?.action || "WARN";
      case "low":
      default:
        return policy.low?.action || "IGNORE";
    }
  }

  /**
   * Evaluate cumulative gate decision across all scan findings.
   */
  static evaluateGateDecision(
    findingsRisk: Array<{
      score: number;
      severity: FindingSeverity;
      decision: PolicyAction;
      category?: string;
      cvss?: number;
    }>,
    policy: SecurityPolicy = DEFAULT_SECURITY_POLICY
  ): { gateResult: "pass" | "fail"; decisionReason: string } {
    let blockCount = 0;
    let reviewCount = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let secretsCount = 0;
    let cvssFailCount = 0;

    for (const f of findingsRisk) {
      if (f.severity === "critical") criticalCount++;
      if (f.severity === "high") highCount++;
      if (f.severity === "medium") mediumCount++;
      if (f.category === "SECRETS") secretsCount++;

      if (
        policy.failOnCvssThreshold &&
        policy.failOnCvssThreshold > 0 &&
        f.cvss !== undefined &&
        f.cvss >= policy.failOnCvssThreshold
      ) {
        cvssFailCount++;
      }

      if (f.decision === "BLOCK") {
        blockCount++;
      } else if (f.decision === "REVIEW") {
        reviewCount++;
      }
    }

    // 1. FAIL if Critical > 0
    if (policy.blockCritical !== false && criticalCount > 0) {
      return {
        gateResult: "fail",
        decisionReason: `Security Gate Failed: Policy violation — ${criticalCount} Critical severity finding(s) detected (Threshold: 0).`
      };
    }

    // 2. FAIL if Secrets > 0
    if (policy.blockSecrets !== false && secretsCount > 0) {
      return {
        gateResult: "fail",
        decisionReason: `Security Gate Failed: Policy violation — ${secretsCount} Exposed Secret(s) detected (Threshold: 0).`
      };
    }

    // 3. FAIL if CVSS >= configured threshold
    if (cvssFailCount > 0) {
      return {
        gateResult: "fail",
        decisionReason: `Security Gate Failed: Policy violation — ${cvssFailCount} finding(s) exceeded configured CVSS threshold >= ${policy.failOnCvssThreshold}.`
      };
    }

    // 4. FAIL if High > 0 or exceeds maxAllowedHigh
    const maxHigh = policy.maxAllowedHigh ?? 0;
    if (policy.blockHigh !== false && highCount > maxHigh) {
      return {
        gateResult: "fail",
        decisionReason: `Security Gate Failed: High severity findings count (${highCount}) exceeds maximum allowed threshold (${maxHigh}).`
      };
    }

    if (blockCount > 0) {
      return {
        gateResult: "fail",
        decisionReason: `Security Gate Failed: ${blockCount} finding(s) met policy BLOCK action criteria.`
      };
    }

    const maxMed = policy.maxAllowedMedium ?? 5;
    if (mediumCount > maxMed) {
      return {
        gateResult: "fail",
        decisionReason: `Security Gate Failed: Medium severity findings count (${mediumCount}) exceeds maximum allowed threshold (${maxMed}).`
      };
    }

    if (reviewCount > 0) {
      return {
        gateResult: "pass",
        decisionReason: `Security Gate Passed with WARNING: ${reviewCount} finding(s) require security team review.`
      };
    }

    return {
      gateResult: "pass",
      decisionReason: "Security Gate Passed: All findings comply with repository security policy."
    };
  }
}
