import { readFile, unlink } from "fs/promises";
import { existsSync } from "fs";
import path from "path";
import crypto from "crypto";
import os from "os";
import { z } from "zod";
import { SecurityScanner, ScannerResult } from "./SecurityScanner";
import { NormalizedFinding } from "./types";
import { executeScannerProcess } from "./scannerExecutor";

const GITLEAKS_TIMEOUT_MS = 3 * 60 * 1000;
const GITLEAKS_CONFIG_PATH = path.resolve(__dirname, "../../../../security/gitleaks/gitleaks.toml");

function resolveGitleaksBinary(): string {
  if (process.env.GITLEAKS_PATH && existsSync(process.env.GITLEAKS_PATH)) {
    return process.env.GITLEAKS_PATH;
  }
  const localAppData = process.env.LOCALAPPDATA || "";
  const candidates = [
    path.join(localAppData, "Microsoft/WinGet/Packages/Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe/gitleaks.exe"),
    path.join(localAppData, "Microsoft/WinGet/Links/gitleaks.exe"),
    path.join(localAppData, "Programs/gitleaks/gitleaks.exe"),
    "gitleaks"
  ];
  for (const c of candidates) {
    if (c === "gitleaks" || existsSync(c)) {
      return c;
    }
  }
  return "gitleaks";
}

const gitleaksResultItemSchema = z.object({
  File: z.string(),
  StartLine: z.number().default(1),
  RuleID: z.string(),
  Secret: z.string().default(""),
  Match: z.string().default("")
});

const gitleaksOutputSchema = z.array(gitleaksResultItemSchema);

export class GitleaksScanner implements SecurityScanner {
  readonly name = "gitleaks" as const;

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const gitleaksBin = resolveGitleaksBinary();
    const reportPath = path.join(os.tmpdir(), `gitleaks-${crypto.randomUUID()}.json`);
    const args = [
      "detect",
      "--source",
      repoPath,
      "--config",
      GITLEAKS_CONFIG_PATH,
      "--report-format",
      "json",
      "--report-path",
      reportPath,
      "--no-git"
    ];

    console.log(`\n--- [GITLEAKS SCAN DEBUG] ---`);
    console.log(`[gitleaks] Target Repository Path: ${repoPath}`);
    console.log(`[gitleaks] Executed Command: ${gitleaksBin} ${args.join(" ")}`);

    try {
      try {
        await executeScannerProcess(
          "gitleaks",
          gitleaksBin,
          args,
          {
            timeoutMs: GITLEAKS_TIMEOUT_MS,
            maxRetries: 1,
            allowedExitCodes: [0, 1] // Gitleaks exits 1 when secrets are found
          }
        );
      } catch (execErr: unknown) {
        const execErrObj = execErr instanceof Error ? execErr : new Error(String(execErr));
        // If binary does not exist, throw clean error
        throw execErrObj;
      }

      let raw = "";
      try {
        raw = await readFile(reportPath, "utf-8");
      } catch {
        // Report file missing means no findings were detected (exit 0)
        return {
          scanner: "gitleaks",
          status: "success",
          findings: [],
          executionTimeMs: Date.now() - startTime
        };
      }

      const parsedJson = JSON.parse(raw || "[]");
      const validated = gitleaksOutputSchema.safeParse(parsedJson);

      if (!validated.success) {
        return {
          scanner: "gitleaks",
          status: "failed",
          findings: [],
          error: `JSON validation failed: ${validated.error.message}`,
          executionTimeMs: Date.now() - startTime
        };
      }

      const findings: NormalizedFinding[] = validated.data.map((item) => {
        const fingerprint = crypto
          .createHash("sha256")
          .update(item.Secret)
          .digest("hex")
          .slice(0, 16);

        return {
          tool: "gitleaks" as const,
          category: "SECRETS" as const,
          file: path.relative(repoPath, item.File).replace(/\\/g, "/"),
          line: item.StartLine,
          ruleId: item.RuleID,
          codeSnippet: item.Match.replace(item.Secret, "[REDACTED]"),
          secretRef: fingerprint,
          cwe: "CWE-798",
          severity: "critical" as const
        };
      });

      return {
        scanner: "gitleaks",
        status: "success",
        findings,
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: unknown) {
      const execErr = err instanceof Error ? err : new Error(String(err));
      console.error("[gitleaks] Scan failed:", execErr.message);
      return {
        scanner: "gitleaks",
        status: "failed",
        findings: [],
        error: execErr.message,
        executionTimeMs: Date.now() - startTime
      };
    } finally {
      await unlink(reportPath).catch(() => {
        /* ignore cleanup error */
      });
    }
  }
}

/**
 * Backward compatibility helper function.
 */
export async function runGitleaksScan(repoPath: string): Promise<NormalizedFinding[]> {
  const scanner = new GitleaksScanner();
  const result = await scanner.scan(repoPath);
  if (result.status === "failed") {
    throw new Error(`[gitleaks] ${result.error || "Scan failed"}`);
  }
  return result.findings;
}