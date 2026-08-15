import { FindingCategory, FindingSeverity, FindingTool } from "../../models/Finding";

/**
 * Common shape every scanner service (Semgrep, Gitleaks, Trivy, OSV, SecretScanner)
 * must normalize its raw output into, before it's saved as a Finding document.
 */
export interface NormalizedFinding {
  tool: FindingTool;
  category?: FindingCategory;
  file: string;
  line: number;
  ruleId: string;
  codeSnippet: string;
  secretRef: string | null;
  secretType?: string;
  isMasked?: boolean;

  // SCA fields
  package?: string;
  installedVersion?: string;
  fixedVersion?: string;
  cve?: string;
  cvss?: number;
  scaRemediation?: string;

  // Container & IaC fields
  resourceName?: string;
  resourceType?: string;
  containerImage?: string;
  iacPlatform?: "docker" | "docker-compose" | "terraform" | "kubernetes" | "generic";
  complianceStandard?: string;

  // CI/CD fields
  workflowName?: string;
  actionName?: string;

  severity: FindingSeverity;
  title?: string;
  description?: string;
  cwe?: string;
}

export class ScannerExecutionError extends Error {
  constructor(tool: FindingTool, message: string) {
    super(`[${tool}] ${message}`);
    this.name = "ScannerExecutionError";
  }
}