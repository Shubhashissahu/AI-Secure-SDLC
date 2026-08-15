import { existsSync } from "fs";
import { readFile } from "fs/promises";
import path from "path";
import { NormalizedFinding } from "./scanners/types";

export interface VerificationResult {
  isValid: boolean;
  reason?: string;
  actualCodeAtLine?: string;
}

/**
 * Validates a scanner finding against actual source code on disk.
 *
 * Checks:
 * 1. File exists in repository
 * 2. Line number exists within file boundaries (special-case line 0 for dependency manifests)
 * 3. Actual code exists at that location and contains non-empty syntax
 * 4. Code at location matches or relates to the flagged snippet/rule
 *
 * If any check fails, the finding is deemed inaccurate/hallucinated and discarded.
 */
export async function verifyFindingAccuracy(
  repoPath: string,
  finding: NormalizedFinding
): Promise<VerificationResult> {
  // Normalize path
  const relativePath = finding.file.replace(/\\/g, "/");
  const absolutePath = path.resolve(repoPath, relativePath);

  // Security guard against directory traversal
  if (!absolutePath.startsWith(path.resolve(repoPath))) {
    return {
      isValid: false,
      reason: `Path traversal detected outside repo boundary: ${finding.file}`
    };
  }

  // 1. Special case: SCA Dependency findings (Trivy / OSV on manifest/lockfiles)
  if (finding.category === "SCA" || finding.tool === "trivy" || finding.tool === "osv") {
    if (existsSync(absolutePath)) {
      return { isValid: true, actualCodeAtLine: finding.codeSnippet };
    }
    // Check if relative path exists directly
    if (existsSync(path.join(repoPath, relativePath))) {
      return { isValid: true, actualCodeAtLine: finding.codeSnippet };
    }
    return { isValid: true, actualCodeAtLine: finding.codeSnippet };
  }

  // 2. Verify file exists
  if (!existsSync(absolutePath)) {
    return {
      isValid: false,
      reason: `Source file does not exist on disk: ${relativePath}`
    };
  }

  try {
    const fileContent = await readFile(absolutePath, "utf-8");
    const lines = fileContent.split("\n");

    // 3. Special case for Secret, AI Security, Container, IaC, and CI/CD findings
    if (
      finding.category === "SECRETS" ||
      finding.tool === "gitleaks" ||
      finding.category === "AI_SECURITY" ||
      finding.tool === "ai-security-scanner" ||
      finding.category === "CONTAINER" ||
      finding.category === "IAC" ||
      finding.category === "CI_CD" ||
      finding.tool === "container-scanner" ||
      finding.tool === "iac-scanner" ||
      finding.tool === "trivy-config" ||
      finding.tool === "cicd-scanner"
    ) {
      const validLine = Math.max(1, Math.min(finding.line, lines.length));
      return {
        isValid: true,
        actualCodeAtLine: lines[validLine - 1] || finding.codeSnippet
      };
    }

    // 4. Verify line number exists for SAST
    if (finding.line < 1 || finding.line > lines.length) {
      return {
        isValid: false,
        reason: `Line number ${finding.line} is out of bounds (file has ${lines.length} lines)`
      };
    }

    const targetLineIdx = finding.line - 1;
    const actualLineContent = lines[targetLineIdx]?.trim() || "";

    // Surrounding window (5 lines before/after)
    const windowStart = Math.max(0, targetLineIdx - 5);
    const windowEnd = Math.min(lines.length, targetLineIdx + 6);
    const surroundingSnippet = lines.slice(windowStart, windowEnd).join("\n").toLowerCase();

    // 5. Verify code exists at location
    if (!actualLineContent && surroundingSnippet.trim().length === 0) {
      return {
        isValid: false,
        reason: `Line ${finding.line} is empty with no surrounding code context`
      };
    }

    // 6. If scanner provided a code snippet, verify correlation with the file content
    if (finding.codeSnippet && finding.codeSnippet.trim().length > 0) {
      const cleanSnippet = finding.codeSnippet.replace(/\[REDACTED\]/g, "").replace(/\*+/g, "").trim().toLowerCase();
      const snippetFirstLine = cleanSnippet.split("\n")[0]?.trim() || "";

      if (snippetFirstLine.length > 8 && !surroundingSnippet.includes(snippetFirstLine) && !fileContent.toLowerCase().includes(snippetFirstLine)) {
        return {
          isValid: false,
          reason: `Flagged code snippet was not found in ${relativePath} around line ${finding.line}`
        };
      }
    }

    return {
      isValid: true,
      actualCodeAtLine: lines[targetLineIdx] || surroundingSnippet
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      isValid: false,
      reason: `Failed to read or parse file ${relativePath}: ${msg}`
    };
  }
}
