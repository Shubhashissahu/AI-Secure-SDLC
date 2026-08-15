import { NormalizedFinding } from "./scanners/types";
import { AiReviewResult } from "./ai/aiReviewerService";
import { FindingSeverity } from "../models/Finding";
import { PolicyEngine, PolicyAction, SecurityPolicy, DEFAULT_SECURITY_POLICY } from "./policyEngine";

export interface RiskResult {
  score: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  decision: PolicyAction;
  severityWeight: number;
  exploitabilityWeight: number;
  businessImpactWeight: number;
  exposureWeight: number;
  assetCriticalityWeight: number;
  authRequiredWeight: number;
  exploitAvailabilityWeight: number;
}

const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  critical: 40,
  high: 30,
  medium: 15,
  low: 5
};

function exploitabilityWeight(review: AiReviewResult): number {
  if (review.reviewFailed) return 18;
  switch (review.exploitability) {
    case "high":
      return 30;
    case "medium":
      return 18;
    case "low":
    default:
      return 6;
  }
}

function assetCriticalityWeight(filePath: string): number {
  const SENSITIVE_PATTERNS = [
    /auth/i, /login/i, /session/i, /token/i, /password/i,
    /credential/i, /payment/i, /billing/i, /admin/i, /\buser/i, /secret/i
  ];
  const matches = SENSITIVE_PATTERNS.filter((pattern) => pattern.test(filePath)).length;
  return Math.min(15, 3 + matches * 4);
}

function exposureWeight(finding: NormalizedFinding): number {
  if (finding.category === "SECRETS" || finding.tool === "gitleaks" || finding.tool === "secret-scanner") return 10;
  if (finding.category === "CI_CD" && /pull-request-target|injection|write-all/i.test(finding.ruleId + " " + finding.title)) return 10;
  if (finding.category === "IAC" && /0\.0\.0\.0|public/i.test(finding.ruleId + " " + finding.title)) return 10;
  if (finding.category === "CONTAINER" && /privileged|socket/i.test(finding.ruleId + " " + finding.title)) return 9;
  if (finding.category === "SCA" || finding.tool === "trivy" || finding.tool === "osv") return 7;
  if (finding.category === "CI_CD") return 8;
  if (/(route|controller|api|handler|endpoint|public)/i.test(finding.file)) return 10;
  if (/(test|spec|__mocks__|__fixtures__|fixture)/i.test(finding.file)) return 1;
  return 5;
}

function authRequiredWeight(filePath: string): number {
  if (/(public|unauth|guest|webhook|health|login|register|\.github\/workflows)/i.test(filePath)) {
    return 5; // Unauthenticated / exposed endpoint or public CI trigger = higher risk
  }
  return 2; // Requires authenticated context
}

function exploitAvailabilityWeight(finding: NormalizedFinding, review: AiReviewResult): number {
  if (finding.category === "SECRETS" || finding.tool === "gitleaks" || finding.tool === "secret-scanner") return 10;
  if (finding.category === "CI_CD" && /pull-request-target|injection|write-all/i.test(finding.ruleId)) return 10;
  if (finding.category === "IAC" && /0\.0\.0\.0|iam-wildcard|privileged/i.test(finding.ruleId)) return 10;
  if (finding.category === "CONTAINER" && /privileged|socket/i.test(finding.ruleId)) return 10;
  if (review.cwe === "CWE-89" || review.cwe === "CWE-78" || review.cwe === "CWE-798") return 10;
  if (review.cwe === "CWE-79") return 7;
  return 4;
}

export function computeRisk(
  finding: NormalizedFinding,
  review: AiReviewResult,
  policy: SecurityPolicy = DEFAULT_SECURITY_POLICY
): RiskResult {
  if (!review.isRealVulnerability && !review.reviewFailed) {
    return {
      score: 0,
      severity: "LOW",
      reason: "Finding verified as FALSE POSITIVE by AI independent reviewer.",
      decision: "IGNORE",
      severityWeight: 0,
      exploitabilityWeight: 0,
      businessImpactWeight: 0,
      exposureWeight: 0,
      assetCriticalityWeight: 0,
      authRequiredWeight: 0,
      exploitAvailabilityWeight: 0
    };
  }

  const sw = SEVERITY_WEIGHTS[finding.severity];
  const ew = exploitabilityWeight(review);
  const bw = assetCriticalityWeight(finding.file);
  const xw = exposureWeight(finding);
  const aw = authRequiredWeight(finding.file);
  const xv = exploitAvailabilityWeight(finding, review);

  const rawScore = sw + ew + bw + xw + aw + xv;

  // Apply AI Confidence factor (0.5 to 1.0 multiplier)
  const confidenceFactor = Math.max(0.5, Math.min(1.0, review.confidence / 100));
  let finalScore = Math.round(rawScore * (0.6 + 0.4 * confidenceFactor));

  // Enforce realistic bounds per finding severity:
  // Critical: 85 - 100
  // High: 65 - 84 (Do not mark system CRITICAL when only High findings exist)
  // Medium: 35 - 64
  // Low: 10 - 34
  switch (finding.severity) {
    case "critical":
      finalScore = Math.max(85, Math.min(100, finalScore));
      break;
    case "high":
      finalScore = Math.max(65, Math.min(84, finalScore));
      break;
    case "medium":
      finalScore = Math.max(35, Math.min(64, finalScore));
      break;
    case "low":
    default:
      finalScore = Math.max(10, Math.min(34, finalScore));
      break;
  }

  let computedSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = "LOW";
  if (finding.severity === "critical") computedSeverity = "CRITICAL";
  else if (finding.severity === "high") computedSeverity = "HIGH";
  else if (finding.severity === "medium") computedSeverity = "MEDIUM";
  else computedSeverity = "LOW";

  const decision = PolicyEngine.evaluateFindingAction(finding.severity, policy);

  const reason = `Risk Score ${finalScore}/100 (${computedSeverity}) calculated from ${finding.severity.toUpperCase()} severity baseline, Exploitability (${ew}), Asset Criticality (${bw}), Exposure (${xw}), Auth Requirement (${aw}), Exploit Availability (${xv}), and AI confidence (${review.confidence}%). Policy action: ${decision}.`;


  return {
    score: finalScore,
    severity: computedSeverity,
    reason,
    decision,
    severityWeight: sw,
    exploitabilityWeight: ew,
    businessImpactWeight: bw,
    exposureWeight: xw,
    assetCriticalityWeight: bw,
    authRequiredWeight: aw,
    exploitAvailabilityWeight: xv
  };
}