import path from "path";
import { existsSync } from "fs";
import { z } from "zod";
import { SecurityScanner, ScannerResult } from "./SecurityScanner";
import { NormalizedFinding } from "./types";
import { FindingSeverity } from "../../models/Finding";
import { executeScannerProcess } from "./scannerExecutor";

const SEMGREP_TIMEOUT_MS = 5 * 60 * 1000; // 5 min ceiling
const SEMGREP_CONFIG_PATH = path.resolve(__dirname, "../../../../security/semgrep");

function resolveSemgrepBinary(): string {
  if (process.env.SEMGREP_PATH && existsSync(process.env.SEMGREP_PATH)) {
    return process.env.SEMGREP_PATH;
  }
  const localAppData = process.env.LOCALAPPDATA || "";
  const candidates = [
    path.join(localAppData, "Programs/Python/Python313/Scripts/semgrep.exe"),
    path.join(localAppData, "Programs/Python/Python312/Scripts/semgrep.exe"),
    path.join(localAppData, "Programs/Python/Python311/Scripts/semgrep.exe"),
    "semgrep"
  ];
  for (const c of candidates) {
    if (c === "semgrep" || existsSync(c)) {
      return c;
    }
  }
  return "semgrep";
}

const semgrepResultItemSchema = z.object({
  path: z.string(),
  start: z.object({ line: z.number().default(1) }),
  check_id: z.string(),
  extra: z.object({
    severity: z.string().default("WARNING"),
    lines: z.string().default(""),
    message: z.string().optional().default(""),
    metadata: z.object({
      cwe: z.union([z.string(), z.array(z.string())]).optional(),
      owasp: z.union([z.string(), z.array(z.string())]).optional(),
      category: z.string().optional()
    }).optional()
  })
});

const semgrepOutputSchema = z.object({
  results: z.array(semgrepResultItemSchema).default([]),
  errors: z.array(z.object({ message: z.string() })).optional().default([])
});

function mapSeverity(semgrepSeverity: string): FindingSeverity {
  switch (semgrepSeverity.toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
    default:
      return "low";
  }
}

export class SemgrepScanner implements SecurityScanner {
  readonly name = "semgrep" as const;

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const semgrepBin = resolveSemgrepBinary();
    const args = ["scan", "--config", SEMGREP_CONFIG_PATH, "--json", repoPath];

    console.log(`\n--- [SEMGREP SCAN DEBUG] ---`);
    console.log(`[semgrep] Target Repository Path: ${repoPath}`);
    console.log(`[semgrep] Executed Command: ${semgrepBin} ${args.join(" ")}`);

    try {
      const execResult = await executeScannerProcess(
        "semgrep",
        semgrepBin,
        args,
        {
          timeoutMs: SEMGREP_TIMEOUT_MS,
          maxRetries: 1,
          allowedExitCodes: [0, 1] // Semgrep exits 0 or 1 when findings are present
        }
      );

      console.log(`[semgrep] Scanner stdout:\n${execResult.stdout?.slice(0, 3000)}`);
      if (execResult.stderr && execResult.stderr.trim().length > 0) {
        console.log(`[semgrep] Scanner stderr:\n${execResult.stderr?.slice(0, 3000)}`);
      }
      console.log(`-----------------------------\n`);

      // Safely extract JSON substring from stdout (in case Semgrep printed banner before JSON)
      let rawJson = execResult.stdout || "{}";
      const firstBrace = rawJson.indexOf("{");
      const lastBrace = rawJson.lastIndexOf("}");
      if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
        rawJson = rawJson.slice(firstBrace, lastBrace + 1);
      }

      const parsedJson = JSON.parse(rawJson);
      const validated = semgrepOutputSchema.safeParse(parsedJson);

      if (!validated.success) {
        return {
          scanner: "semgrep",
          status: "failed",
          findings: [],
          error: `JSON validation failed: ${validated.error.message}`,
          executionTimeMs: Date.now() - startTime
        };
      }

      const findings: NormalizedFinding[] = validated.data.results.map((item) => {
        // Extract clean rule ID (e.g. "java-sql-injection" from "security.semgrep.java-rules.java-sql-injection")
        const ruleIdParts = item.check_id.split(".");
        const ruleId = ruleIdParts[ruleIdParts.length - 1] || item.check_id;

        // Normalize CWE accurately
        let cwe = "CWE-89";
        if (item.extra.metadata?.cwe) {
          const rawCwe = Array.isArray(item.extra.metadata.cwe) ? item.extra.metadata.cwe[0] : item.extra.metadata.cwe;
          const match = String(rawCwe).match(/CWE-\d+/i);
          cwe = match ? match[0].toUpperCase() : String(rawCwe);
        } else {
          const ruleIdLower = ruleId.toLowerCase();
          if (ruleIdLower.includes("sql") || ruleIdLower.includes("sqli")) {
            cwe = "CWE-89";
          } else if (ruleIdLower.includes("xss") || ruleIdLower.includes("inner-html")) {
            cwe = "CWE-79";
          } else if (ruleIdLower.includes("exec") || ruleIdLower.includes("command")) {
            cwe = "CWE-78";
          } else if (ruleIdLower.includes("traversal") || ruleIdLower.includes("path")) {
            cwe = "CWE-22";
          } else if (ruleIdLower.includes("deserializ")) {
            cwe = "CWE-502";
          } else if (ruleIdLower.includes("ssrf")) {
            cwe = "CWE-918";
          } else if (ruleIdLower.includes("password") || ruleIdLower.includes("credential") || ruleIdLower.includes("secret") || ruleIdLower.includes("key") || ruleIdLower.includes("token")) {
            cwe = "CWE-798";
          } else if (ruleIdLower.includes("weak-crypt") || ruleIdLower.includes("des") || ruleIdLower.includes("rc4") || ruleIdLower.includes("cipher")) {
            cwe = "CWE-327";
          } else if (ruleIdLower.includes("hash") || ruleIdLower.includes("md5") || ruleIdLower.includes("sha1")) {
            cwe = "CWE-916";
          } else if (ruleIdLower.includes("redirect")) {
            cwe = "CWE-601";
          } else if (ruleIdLower.includes("upload") || ruleIdLower.includes("file-upload")) {
            cwe = "CWE-434";
          } else if (ruleIdLower.includes("xxe") || ruleIdLower.includes("xml")) {
            cwe = "CWE-611";
          } else if (ruleIdLower.includes("ldap")) {
            cwe = "CWE-90";
          } else if (ruleIdLower.includes("nosql") || ruleIdLower.includes("mongo")) {
            cwe = "CWE-943";
          } else if (ruleIdLower.includes("pollution") || ruleIdLower.includes("proto")) {
            cwe = "CWE-1321";
          } else if (ruleIdLower.includes("redos") || ruleIdLower.includes("regex")) {
            cwe = "CWE-1333";
          }
        }


        // Relative normalized path
        const relativeFilePath = path.relative(repoPath, item.path).replace(/\\/g, "/");

        return {
          tool: "semgrep" as const,
          file: relativeFilePath,
          line: item.start.line,
          ruleId,
          codeSnippet: item.extra.lines.slice(0, 2000),
          secretRef: null,
          severity: mapSeverity(item.extra.severity),
          description: item.extra.message,
          cwe
        };
      });

      return {
        scanner: "semgrep",
        status: "success",
        findings,
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: unknown) {
      const execErr = err instanceof Error ? err : new Error(String(err));

      console.error("[semgrep] Scan failed:", execErr.message);
      return {
        scanner: "semgrep",
        status: "failed",
        findings: [],
        error: execErr.message,
        executionTimeMs: Date.now() - startTime
      };
    }
  }
}

/**
 * Backward compatibility helper function.
 */
export async function runSemgrepScan(repoPath: string): Promise<NormalizedFinding[]> {
  const scanner = new SemgrepScanner();
  const result = await scanner.scan(repoPath);
  if (result.status === "failed") {
    throw new Error(`[semgrep] ${result.error || "Scan failed"}`);
  }
  return result.findings;
}