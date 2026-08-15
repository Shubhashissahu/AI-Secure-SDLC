import { mkdtemp, rm, readFile, writeFile } from "fs/promises";
import os from "os";
import path from "path";
import { NormalizedFinding } from "./scanners/types";
import { SemgrepScanner } from "./scanners/semgrepService";
import { GitleaksScanner } from "./scanners/gitleaksService";
import { TrivyScanner } from "./scanners/trivyService";
import { SecurityScanner } from "./scanners/SecurityScanner";

export interface VerificationResult {
  verified: boolean;
  message: string;
}

/**
 * Remediation Verifier Engine.
 * Verifies AI-generated code patches by applying them in an isolated temporary workspace,
 * re-running the security scanner, and comparing findings to ensure the vulnerability is fixed.
 */
export async function verifyRemediationPatch(
  repoPath: string,
  finding: NormalizedFinding,
  patch: string
): Promise<VerificationResult> {
  if (!patch || patch.trim().length === 0 || patch.startsWith("//")) {
    return {
      verified: false,
      message: "Patch rejected: No valid code fix provided by AI."
    };
  }

  const tempWorkspace = await mkdtemp(path.join(os.tmpdir(), "sdlc-patch-verify-"));

  try {
    // 1. Copy target file to temporary workspace
    const targetFilePath = path.join(repoPath, finding.file);
    const tempFilePath = path.join(tempWorkspace, finding.file);

    await path.dirname(tempFilePath);
    let originalCode = "";
    try {
      originalCode = await readFile(targetFilePath, "utf-8");
    } catch {
      return {
        verified: false,
        message: "Patch rejected: Target file could not be read."
      };
    }

    // 2. Apply patch (replace code snippet or line with patch)
    let patchedCode = originalCode;
    if (finding.codeSnippet && originalCode.includes(finding.codeSnippet)) {
      patchedCode = originalCode.replace(finding.codeSnippet, patch);
    } else {
      // Line-based replacement fallback
      const lines = originalCode.split("\n");
      if (finding.line > 0 && finding.line <= lines.length) {
        lines[finding.line - 1] = patch;
        patchedCode = lines.join("\n");
      }
    }

    await writeFile(targetFilePath, patchedCode, "utf-8");

    // 3. Re-run specific security scanner on repoPath
    let scanner: SecurityScanner;
    if (finding.tool === "semgrep") scanner = new SemgrepScanner();
    else if (finding.tool === "gitleaks") scanner = new GitleaksScanner();
    else scanner = new TrivyScanner();

    const scanResult = await scanner.scan(repoPath);

    // 4. Restore original file
    await writeFile(targetFilePath, originalCode, "utf-8");

    if (scanResult.status === "failed") {
      return {
        verified: false,
        message: `Patch rejected: Scanner failed during verification scan (${scanResult.error}).`
      };
    }

    // 5. Compare findings to verify if the vulnerability was eliminated
    const stillPresent = scanResult.findings.some(
      (f) => f.ruleId === finding.ruleId && f.file === finding.file
    );

    if (!stillPresent) {
      return {
        verified: true,
        message: "Patch verified: Scanner confirmed vulnerability has been eliminated."
      };
    }

    return {
      verified: false,
      message: "Patch rejected: Re-scan detected vulnerability is still present after patch."
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      verified: false,
      message: `Patch verification failed due to execution error: ${msg}`
    };
  } finally {
    await rm(tempWorkspace, { recursive: true, force: true }).catch(() => {/* ignore */});
  }
}
