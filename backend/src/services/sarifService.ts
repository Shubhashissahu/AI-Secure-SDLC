import { IFinding } from "../models/Finding";
import { IScan } from "../models/Scan";

export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri?: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  properties?: {
    cwe?: string;
    owasp?: string;
    precision?: string;
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; snippet?: { text: string } };
    };
  }>;
  properties: {
    risk_score?: number;
    ai_confidence?: number;
    ai_confirmed?: boolean;
    cwe?: string;
    owasp?: string;
    exploitability?: string;
    decision?: string;
  };
}

/**
 * Converts normalized findings and scan metadata into official OASIS SARIF v2.1.0 standard.
 */
export class SarifService {
  static generateSarif(_scan: IScan, findings: IFinding[]): SarifLog {
    const rulesMap = new Map<string, SarifRule>();

    findings.forEach((f) => {
      if (!rulesMap.has(f.ruleId)) {
        rulesMap.set(f.ruleId, {
          id: f.ruleId,
          name: f.ruleId.replace(/[^a-zA-Z0-9-]/g, "_"),
          shortDescription: { text: `Security Finding: ${f.ruleId}` },
          fullDescription: { text: f.ai?.attackScenario || `Security vulnerability detected by ${f.tool}` },
          properties: {
            cwe: f.ai?.cwe || "CWE-200",
            owasp: f.ai?.owasp || "N/A",
            precision: f.ai?.confidence && f.ai.confidence > 80 ? "high" : "medium"
          }
        });
      }
    });

    const rules = Array.from(rulesMap.values());
    const ruleIdToIndex = new Map(rules.map((r, i) => [r.id, i]));

    const sarifResults: SarifResult[] = findings.map((f) => {
      let level: "error" | "warning" | "note" = "warning";
      if (f.severity === "critical" || f.severity === "high") {
        level = "error";
      } else if (f.severity === "low") {
        level = "note";
      }

      return {
        ruleId: f.ruleId,
        ruleIndex: ruleIdToIndex.get(f.ruleId),
        level,
        message: {
          text: `[${f.severity.toUpperCase()}] ${f.ai?.attackScenario || f.codeSnippet}`
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: {
                startLine: Math.max(1, f.line),
                snippet: { text: f.codeSnippet }
              }
            }
          }
        ],
        properties: {
          risk_score: f.risk?.score,
          ai_confidence: f.ai?.confidence,
          ai_confirmed: f.ai?.isRealVulnerability,
          cwe: f.ai?.cwe,
          owasp: f.ai?.owasp,
          exploitability: f.ai?.exploitability,
          decision: f.risk?.decision
        }
      };
    });

    return {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "ai-secure-sdlc-platform",
              version: "1.0.0",
              informationUri: "https://github.com/ai-secure-sdlc",
              rules
            }
          },
          results: sarifResults
        }
      ]
    };
  }

  static exportSarifJson(scan: IScan, findings: IFinding[]): string {
    const sarifLog = SarifService.generateSarif(scan, findings);
    return JSON.stringify(sarifLog, null, 2);
  }
}
