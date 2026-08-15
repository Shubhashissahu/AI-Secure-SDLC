import { IFinding } from "../models/Finding";
import { IScan } from "../models/Scan";
import { SarifService } from "./sarifService";

export interface SecurityReport {
  scanId: string;
  timestamp: Date;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    highestRiskScore: number;
    averageRiskScore: number;
  };
  findings: Array<{
    id: string;
    severity: string;
    file: string;
    line: number;
    ruleId: string;
    status: string;
    ai?: {
      confidence: number;
      attackScenario: string;
      remediation: {
        explanation: string;
      };
    };
  }>;
  recommendations: string[];
  gateStatus: "pass" | "fail" | "pending";
  timestamp_generated: Date;
}

/**
 * Report generation service.
 * Creates comprehensive security reports for scans.
 */
export class ReportService {
  /**
   * Generate a full security report for a scan.
   */
  static generateReport(scan: IScan, findings: IFinding[]): SecurityReport {
    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const highCount = findings.filter((f) => f.severity === "high").length;
    const mediumCount = findings.filter((f) => f.severity === "medium").length;
    const lowCount = findings.filter((f) => f.severity === "low").length;

    const riskScores = findings
      .filter((f) => f.risk?.score)
      .map((f) => f.risk!.score);
    const highestRiskScore = riskScores.length > 0 ? Math.max(...riskScores) : 0;
    const averageRiskScore =
      riskScores.length > 0
        ? Math.round(riskScores.reduce((a, b) => a + b, 0) / riskScores.length)
        : 0;

    return {
      scanId: scan._id.toString(),
      timestamp: scan.startedAt,
      summary: {
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        total: findings.length,
        highestRiskScore,
        averageRiskScore
      },
      findings: findings.map((f) => ({
        id: f._id.toString(),
        severity: f.severity,
        file: f.file,
        line: f.line,
        ruleId: f.ruleId,
        status: f.status,
        ai: f.ai
      })),
      recommendations: ReportService.generateRecommendations(scan, findings),
      gateStatus: scan.gateResult,
      timestamp_generated: new Date()
    };
  }

  private static generateRecommendations(
    _scan: IScan,
    findings: IFinding[]
  ): string[] {
    const recommendations: string[] = [];

    // Critical findings
    const criticals = findings.filter((f) => f.severity === "critical");
    if (criticals.length > 0) {
      recommendations.push(
        `🔴 **CRITICAL**: Address ${criticals.length} critical finding(s) before merge. ` +
          criticals
            .slice(0, 3)
            .map((f) => f.ruleId)
            .join(", ") +
          (criticals.length > 3 ? `, and ${criticals.length - 3} more` : "")
      );
    }

    // High findings
    const highs = findings.filter((f) => f.severity === "high");
    if (highs.length > 0) {
      recommendations.push(
        `🟠 **HIGH**: Review and remediate ${highs.length} high-severity finding(s).`
      );
    }

    // Medium findings
    const mediums = findings.filter((f) => f.severity === "medium");
    if (mediums.length > 0 && mediums.length <= 5) {
      recommendations.push(
        `🟡 **MEDIUM**: Consider addressing ${mediums.length} medium-severity finding(s).`
      );
    } else if (mediums.length > 5) {
      recommendations.push(
        `🟡 **MEDIUM**: ${mediums.length} medium-severity findings detected. ` +
          "Review and remediate according to your team's risk tolerance."
      );
    }

    // No findings
    if (findings.length === 0) {
      recommendations.push("✅ **PASS**: No security findings detected. Ready to merge.");
    }

    // AI confidence notes
    const lowConfidence = findings.filter(
      (f) => f.ai && f.ai.confidence < 60
    );
    if (lowConfidence.length > 0) {
      recommendations.push(
        `ℹ️ ${lowConfidence.length} finding(s) have low AI confidence. ` +
          "Manual review recommended."
      );
    }

    return recommendations;
  }

  static generatePRComment(scan: IScan, findings: IFinding[]): string {
    const summary = scan.summary;
    const isPass = scan.gateResult === "pass";
    const decisionText = isPass ? "ALLOW MERGE" : "BLOCK MERGE";
    const gateIcon = isPass ? "✅" : "❌";

    const lines = [
      `## 🛡️ AI Security Review`,
      "",
      `**Decision**: ${gateIcon} **${decisionText}**`,
      "",
      `| Severity | Count |`,
      `|---|---|`,
      `| 🔴 Critical | ${summary.critical} |`,
      `| 🟠 High | ${summary.high} |`,
      `| 🟡 Medium | ${summary.medium} |`,
      `| 🟢 Low | ${summary.low} |`,
      "",
      `### Findings Breakdown`
    ];

    if (findings.length === 0) {
      lines.push("\n✨ **All Clear!** No security findings detected in this Pull Request.");
    } else {
      lines.push(
        `| Finding / Rule | Location | AI Validation | Confidence | Risk Score | Decision |`,
        `|---|---|---|---|---|---|`
      );

      for (const f of findings.slice(0, 10)) {
        const isConfirmed = f.ai?.isRealVulnerability ?? true;
        const validationText = isConfirmed ? "Confirmed" : "False Positive";
        const confidenceText = `${f.ai?.confidence ?? 80}%`;
        const riskScoreText = `${f.risk?.score ?? 0}/100`;
        const itemDecision = f.risk?.decision || (f.severity === "critical" || f.severity === "high" ? "BLOCK" : "WARN");

        lines.push(
          `| **${f.ruleId}** | \`${f.file}:${f.line}\` | ${validationText} | ${confidenceText} | ${riskScoreText} | **${itemDecision}** |`
        );
      }

      if (findings.length > 10) {
        lines.push(`\n*... and ${findings.length - 10} additional finding(s).*`);
      }
    }

    lines.push(`\n---`, `*Powered by AI Secure SDLC Platform*`);

    return lines.join("\n");
  }

  /**
   * Export report as JSON.
   */
  static exportJSON(report: SecurityReport): string {
    return JSON.stringify(report, null, 2);
  }

  /**
   * Export report as SARIF format (OASIS v2.1.0 standard).
   */
  static exportSARIF(scan: IScan, findings: IFinding[]): string {
    return SarifService.exportSarifJson(scan, findings);
  }
}
