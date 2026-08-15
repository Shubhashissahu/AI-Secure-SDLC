import { FindingTool } from "../../models/Finding";
import { NormalizedFinding } from "./types";

export type ScannerStatus = "success" | "failed";

export interface ScannerResult {
  scanner: FindingTool;
  status: ScannerStatus;
  findings: NormalizedFinding[];
  error?: string;
  executionTimeMs: number;
}

/**
  * Standard Security Scanner Interface.
  * Every scanner (Semgrep, Gitleaks, Trivy) must implement this contract.
  */
export interface SecurityScanner {
  readonly name: FindingTool;
  scan(repositoryPath: string): Promise<ScannerResult>;
}
