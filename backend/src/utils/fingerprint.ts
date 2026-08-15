import crypto from "crypto";

/**
 * Generates a deterministic SHA256 fingerprint for a finding.
 *
 * finding_hash = SHA256(
 *   repository_id +
 *   commit_hash +
 *   file_path +
 *   line_number +
 *   rule_id +
 *   vulnerability_type
 * )
 */
export function generateFindingFingerprint(
  repositoryId: string,
  commitSha: string,
  filePath: string,
  lineNumber: number,
  ruleId: string,
  vulnerabilityType: string = "vulnerability"
): string {
  // Normalize components
  const normRepoId = String(repositoryId || "").trim();
  const normCommit = String(commitSha || "").trim();
  const normFile = String(filePath || "").replace(/\\/g, "/").trim().toLowerCase();
  const normLine = Number(lineNumber) || 0;
  const normRule = String(ruleId || "").trim().toLowerCase();
  const normType = String(vulnerabilityType || "vulnerability").trim().toLowerCase();

  const payload = `${normRepoId}:${normCommit}:${normFile}:${normLine}:${normRule}:${normType}`;

  return crypto.createHash("sha256").update(payload).digest("hex");
}

/**
 * Generates a repository-scoped signature independent of commit SHA,
 * useful for tracking the lifecycle and resolution of a vulnerability across commits.
 */
export function generateVulnerabilitySignature(
  repositoryId: string,
  filePath: string,
  lineNumber: number,
  ruleId: string
): string {
  const normRepoId = String(repositoryId || "").trim();
  const normFile = String(filePath || "").replace(/\\/g, "/").trim().toLowerCase();
  const normLine = Number(lineNumber) || 0;
  const normRule = String(ruleId || "").trim().toLowerCase();

  return crypto.createHash("sha256").update(`${normRepoId}:${normFile}:${normLine}:${normRule}`).digest("hex");
}
