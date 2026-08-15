import path from "path";
import os from "os";
import { existsSync } from "fs";
import { z } from "zod";
import { SecurityScanner, ScannerResult } from "./SecurityScanner";
import { NormalizedFinding } from "./types";
import { FindingSeverity } from "../../models/Finding";
import { executeScannerProcess } from "./scannerExecutor";

const TRIVY_TIMEOUT_MS = 5 * 60 * 1000;

function resolveTrivyBinary(): string {
  if (process.env.TRIVY_PATH && existsSync(process.env.TRIVY_PATH)) {
    return process.env.TRIVY_PATH;
  }
  const localAppData = process.env.LOCALAPPDATA || "";
  const candidates = [
    path.join(localAppData, "Microsoft/WinGet/Packages/AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe/trivy.exe"),
    path.join(localAppData, "Microsoft/WinGet/Links/trivy.exe"),
    path.join(localAppData, "Programs/trivy/trivy.exe"),
    "trivy"
  ];
  for (const c of candidates) {
    if (c === "trivy" || existsSync(c)) {
      return c;
    }
  }
  return "trivy";
}

const trivyVulnerabilitySchema = z.object({
  VulnerabilityID: z.string(),
  PkgName: z.string().default("unknown"),
  InstalledVersion: z.string().default("0.0.0"),
  FixedVersion: z.string().optional(),
  Severity: z.string().default("LOW"),
  Title: z.string().optional(),
  Description: z.string().optional(),
  CVSS: z.record(z.object({ V3Score: z.number().optional(), V2Score: z.number().optional() })).optional(),
  PrimaryURL: z.string().optional()
});

const trivyResultSchema = z.object({
  Target: z.string(),
  Vulnerabilities: z.array(trivyVulnerabilitySchema).optional().default([])
});

const trivyOutputSchema = z.object({
  Results: z.array(trivyResultSchema).optional().default([])
});

function mapSeverity(trivySeverity: string): FindingSeverity {
  switch (trivySeverity.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
    case "UNKNOWN":
    default:
      return "low";
  }
}

export class TrivyScanner implements SecurityScanner {
  readonly name = "trivy" as const;

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const trivyBin = resolveTrivyBinary();
    const args = ["fs", "--format", "json", "--quiet", repoPath];

    console.log(`\n--- [TRIVY SCAN DEBUG] ---`);
    console.log(`[trivy] Target Repository Path: ${repoPath}`);
    console.log(`[trivy] Executed Command: ${trivyBin} ${args.join(" ")}`);

    try {
      const execResult = await executeScannerProcess(
        "trivy",
        trivyBin,
        args,
        {
          timeoutMs: TRIVY_TIMEOUT_MS,
          maxRetries: 1,
          allowedExitCodes: [0],
          env: {
            ...process.env,
            DOCKER_CONFIG: os.tmpdir()
          }
        }
      );

      const parsedJson = JSON.parse(execResult.stdout || "{}");
      const validated = trivyOutputSchema.safeParse(parsedJson);

      if (!validated.success) {
        return {
          scanner: "trivy",
          status: "failed",
          findings: [],
          error: `JSON validation failed: ${validated.error.message}`,
          executionTimeMs: Date.now() - startTime
        };
      }

      const findings: NormalizedFinding[] = [];
      for (const res of validated.data.Results || []) {
        for (const vuln of res.Vulnerabilities || []) {
          // Extract CVSS score
          let cvssScore: number | undefined;
          if (vuln.CVSS) {
            for (const cvssData of Object.values(vuln.CVSS)) {
              if (cvssData?.V3Score) {
                cvssScore = cvssData.V3Score;
                break;
              } else if (cvssData?.V2Score) {
                cvssScore = cvssData.V2Score;
              }
            }
          }

          const remediationText = vuln.FixedVersion
            ? `Upgrade ${vuln.PkgName} from ${vuln.InstalledVersion} to >= ${vuln.FixedVersion}`
            : `Check security advisory for ${vuln.PkgName}@${vuln.InstalledVersion}`;

          findings.push({
            tool: "trivy",
            category: "SCA",
            file: path.relative(repoPath, res.Target) || res.Target,
            line: 1,
            ruleId: vuln.VulnerabilityID,
            title: `${vuln.VulnerabilityID}: ${vuln.PkgName}@${vuln.InstalledVersion}`,
            description: vuln.Title || vuln.Description || `Vulnerability in ${vuln.PkgName}`,
            codeSnippet: [
              `Target: ${res.Target}`,
              `Package: ${vuln.PkgName}`,
              `Installed Version: ${vuln.InstalledVersion}`,
              vuln.FixedVersion ? `Fixed in: ${vuln.FixedVersion}` : "No fixed version available yet",
              `CVE: ${vuln.VulnerabilityID}`,
              cvssScore ? `CVSS Score: ${cvssScore}` : "",
              vuln.Title || vuln.Description || ""
            ]
              .filter(Boolean)
              .join("\n")
              .slice(0, 2000),
            secretRef: null,
            package: vuln.PkgName,
            installedVersion: vuln.InstalledVersion,
            fixedVersion: vuln.FixedVersion,
            cve: vuln.VulnerabilityID,
            cvss: cvssScore,
            scaRemediation: remediationText,
            cwe: "CWE-1395",
            severity: mapSeverity(vuln.Severity)
          });
        }
      }

      return {
        scanner: "trivy",
        status: "success",
        findings,
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: unknown) {
      const execErr = err instanceof Error ? err : new Error(String(err));

      console.error("[trivy] Scan failed:", execErr.message);
      return {
        scanner: "trivy",
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
export async function runTrivyScan(repoPath: string): Promise<NormalizedFinding[]> {
  const scanner = new TrivyScanner();
  const result = await scanner.scan(repoPath);
  if (result.status === "failed") {
    throw new Error(`[trivy] ${result.error || "Scan failed"}`);
  }
  return result.findings;
}