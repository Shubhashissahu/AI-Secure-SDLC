import { readFile, readdir, stat } from "fs/promises";
import { existsSync } from "fs";
import path from "path";
import os from "os";
import { SecurityScanner, ScannerResult } from "./SecurityScanner";
import { NormalizedFinding } from "./types";
import { executeScannerProcess } from "./scannerExecutor";
import { maskAllSecretsInText } from "../../utils/secretMasker";
import { FindingSeverity } from "../../models/Finding";

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

function mapTrivySeverity(sev: string): FindingSeverity {
  switch (sev?.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
    default:
      return "low";
  }
}

export class ContainerScanner implements SecurityScanner {
  readonly name = "container-scanner" as const;

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: NormalizedFinding[] = [];
    const seenKeys = new Set<string>();

    try {
      // 1. Run Trivy Config scanner for real container / docker misconfigurations
      const trivyBin = resolveTrivyBinary();
      try {
        const execResult = await executeScannerProcess(
          "trivy-config",
          trivyBin,
          ["config", "--format", "json", "--quiet", repoPath],
          {
            timeoutMs: 3 * 60 * 1000,
            maxRetries: 1,
            allowedExitCodes: [0],
            env: {
              ...process.env,
              DOCKER_CONFIG: os.tmpdir()
            }
          }
        );

        const parsedJson = JSON.parse(execResult.stdout || "{}");
        const results = parsedJson.Results || [];

        for (const res of results) {
          const target = res.Target || "";
          const isDockerTarget =
            target.toLowerCase().includes("dockerfile") ||
            target.toLowerCase().includes("docker-compose") ||
            target.toLowerCase().includes("compose.y");

          if (isDockerTarget && res.Misconfigurations) {
            for (const misconf of res.Misconfigurations) {
              const relFile = path.relative(repoPath, target) || target;
              const ruleId = misconf.ID || misconf.AVDID || "CONTAINER-MISCONFIG";
              const key = `${relFile}:${misconf.Resolution?.Line || 1}:${ruleId}`;

              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                const sev = mapTrivySeverity(misconf.Severity);
                const title = misconf.Title || misconf.Description || ruleId;
                const remediation = misconf.Resolution || "Follow CIS Docker Benchmark guidelines.";

                findings.push({
                  tool: "trivy-config",
                  category: "CONTAINER",
                  file: relFile.replace(/\\/g, "/"),
                  line: misconf.Resolution?.Line || 1,
                  ruleId,
                  title,
                  description: misconf.Description || title,
                  codeSnippet: maskAllSecretsInText(
                    `Target: ${relFile}\nIssue: ${title}\nRemediation: ${remediation}\nMessage: ${misconf.Message || ""}`
                  ),
                  secretRef: null,
                  iacPlatform: target.toLowerCase().includes("compose") ? "docker-compose" : "docker",
                  complianceStandard: "CIS Docker Benchmark",
                  scaRemediation: remediation,
                  severity: sev,
                  cwe: "CWE-250"
                });
              }
            }
          }
        }
      } catch (trivyErr: unknown) {
        console.warn("[ContainerScanner] Trivy config note:", trivyErr instanceof Error ? trivyErr.message : String(trivyErr));
      }

      // 2. Perform deep static analysis on Dockerfile and docker-compose files
      const files = await getAllFiles(repoPath);

      for (const relFile of files) {
        const fullPath = path.join(repoPath, relFile);
        const filename = path.basename(relFile).toLowerCase();

        // ── Dockerfile Analysis ───────────────────────────────────
        if (filename === "dockerfile" || filename.startsWith("dockerfile.") || filename.endsWith(".dockerfile")) {
          const content = await readFile(fullPath, "utf-8").catch(() => "");
          if (!content) continue;

          const lines = content.split("\n");
          let hasUserDirective = false;
          let hasHealthcheck = false;

          lines.forEach((line, idx) => {
            const lineNum = idx + 1;
            const trimmed = line.trim();

            if (trimmed.startsWith("#")) return;

            // 1. Latest tag detection
            const fromMatch = trimmed.match(/^FROM\s+([^\s]+)/i);
            if (fromMatch) {
              const image = fromMatch[1];
              if (!image.includes(":") || image.endsWith(":latest")) {
                const key = `${relFile}:${lineNum}:docker-image-latest-tag`;
                if (!seenKeys.has(key)) {
                  seenKeys.add(key);
                  findings.push({
                    tool: "container-scanner",
                    category: "CONTAINER",
                    file: relFile.replace(/\\/g, "/"),
                    line: lineNum,
                    ruleId: "docker-image-latest-tag",
                    title: "Container Image Uses ':latest' or Unpinned Tag",
                    description: `Image '${image}' in FROM directive is not pinned to a specific immutable version SHA or release tag. This can lead to non-deterministic builds and supply-chain vulnerabilities.`,
                    codeSnippet: line,
                    secretRef: null,
                    containerImage: image,
                    iacPlatform: "docker",
                    complianceStandard: "CIS Docker Benchmark 4.3",
                    scaRemediation: `Pin the base image to a verified digest or explicit minor version tag (e.g. '${image.split(":")[0]}:18.19.0-alpine').`,
                    severity: "medium",
                    cwe: "CWE-1395"
                  });
                }
              }
            }

            // 2. USER directive check
            if (/^USER\s+/i.test(trimmed)) {
              hasUserDirective = true;
              if (/^USER\s+(root|0)/i.test(trimmed)) {
                const key = `${relFile}:${lineNum}:docker-running-as-root`;
                if (!seenKeys.has(key)) {
                  seenKeys.add(key);
                  findings.push({
                    tool: "container-scanner",
                    category: "CONTAINER",
                    file: relFile.replace(/\\/g, "/"),
                    line: lineNum,
                    ruleId: "docker-running-as-root",
                    title: "Container Explicitly Configured to Run as Root",
                    description: "Container process runs with root privileges (UID 0), granting full host root access in the event of container breakout.",
                    codeSnippet: line,
                    secretRef: null,
                    iacPlatform: "docker",
                    complianceStandard: "CIS Docker Benchmark 4.1",
                    scaRemediation: "Create and switch to a dedicated non-root user (e.g. 'USER appuser' or 'USER 10001:10001').",
                    severity: "high",
                    cwe: "CWE-250"
                  });
                }
              }
            }

            // 3. HEALTHCHECK check
            if (/^HEALTHCHECK\s+/i.test(trimmed)) {
              hasHealthcheck = true;
            }

            // 4. Exposed secrets in ENV / ARG
            const secretMatch = trimmed.match(/^(?:ENV|ARG)\s+([A-Z0-9_-]*(?:KEY|SECRET|PASSWORD|PASS|TOKEN|CREDENTIAL)[A-Z0-9_-]*)\s*=\s*(.+)/i);
            if (secretMatch) {
              const varName = secretMatch[1];
              const varVal = secretMatch[2];
              if (varVal && !varVal.startsWith("$") && varVal.length > 3) {
                const key = `${relFile}:${lineNum}:docker-exposed-secret-env`;
                if (!seenKeys.has(key)) {
                  seenKeys.add(key);
                  findings.push({
                    tool: "container-scanner",
                    category: "CONTAINER",
                    file: relFile.replace(/\\/g, "/"),
                    line: lineNum,
                    ruleId: "docker-exposed-secret-env",
                    title: `Hardcoded Secret in Dockerfile Directive (${varName})`,
                    description: `Sensitive credential stored in ${trimmed.split(" ")[0]} directive will be baked into immutable container image layers and visible via 'docker history'.`,
                    codeSnippet: maskAllSecretsInText(line),
                    secretRef: null,
                    isMasked: true,
                    iacPlatform: "docker",
                    complianceStandard: "CIS Docker Benchmark 4.8",
                    scaRemediation: "Pass secrets securely at runtime using Docker BuildKit secret mounts (--mount=type=secret) or runtime environment variables.",
                    severity: "critical",
                    cwe: "CWE-798"
                  });
                }
              }
            }

            // 5. Dangerous tools installed (sudo, netcat, telnet)
            if (/RUN\s+.*(apt-get|apk|yum)\s+install.*(sudo|telnet|netcat|nmap|gdb)/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:docker-unsafe-packages`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "container-scanner",
                  category: "CONTAINER",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "docker-unsafe-packages",
                  title: "High-Risk Diagnostic or Privilege Escalation Tool Installed in Image",
                  description: "Installing sudo, netcat, telnet or debugging tools increases the attack surface for container breakout and lateral movement.",
                  codeSnippet: line,
                  secretRef: null,
                  iacPlatform: "docker",
                  complianceStandard: "CIS Docker Benchmark 4.4",
                  scaRemediation: "Remove unnecessary administration and network debugging utilities from production container images.",
                  severity: "medium",
                  cwe: "CWE-250"
                });
              }
            }
          });

          // Check if USER directive was completely missing
          if (!hasUserDirective && lines.length > 2) {
            const key = `${relFile}:1:docker-missing-user-nonroot`;
            if (!seenKeys.has(key)) {
              seenKeys.add(key);
              findings.push({
                tool: "container-scanner",
                category: "CONTAINER",
                file: relFile.replace(/\\/g, "/"),
                line: 1,
                ruleId: "docker-missing-user-nonroot",
                title: "Dockerfile Missing Non-Root USER Instruction",
                description: "No 'USER' directive specified in Dockerfile. The container will execute as root by default, which violates the principle of least privilege.",
                codeSnippet: lines.slice(0, 5).join("\n"),
                secretRef: null,
                iacPlatform: "docker",
                complianceStandard: "CIS Docker Benchmark 4.1",
                scaRemediation: "Add 'RUN addgroup -S appgroup && adduser -S appuser -G appgroup' followed by 'USER appuser' before CMD/ENTRYPOINT.",
                severity: "high",
                cwe: "CWE-250"
              });
            }
          }

          // Check if HEALTHCHECK is missing
          if (!hasHealthcheck && lines.length > 3) {
            const key = `${relFile}:1:docker-missing-healthcheck`;
            if (!seenKeys.has(key)) {
              seenKeys.add(key);
              findings.push({
                tool: "container-scanner",
                category: "CONTAINER",
                file: relFile.replace(/\\/g, "/"),
                line: 1,
                ruleId: "docker-missing-healthcheck",
                title: "Dockerfile Missing HEALTHCHECK Instruction",
                description: "Containers without a HEALTHCHECK instruction cannot notify the orchestrator (Kubernetes/Docker Swarm) when a service has hung or failed.",
                codeSnippet: lines[0] || "FROM ...",
                secretRef: null,
                iacPlatform: "docker",
                complianceStandard: "CIS Docker Benchmark 4.6",
                scaRemediation: "Add 'HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/health || exit 1'.",
                severity: "low",
                cwe: "CWE-693"
              });
            }
          }
        }

        // ── docker-compose.yml / yaml Analysis ───────────────────
        else if (
          filename === "docker-compose.yml" ||
          filename === "docker-compose.yaml" ||
          filename === "compose.yml" ||
          filename === "compose.yaml"
        ) {
          const content = await readFile(fullPath, "utf-8").catch(() => "");
          if (!content) continue;

          const lines = content.split("\n");

          lines.forEach((line, idx) => {
            const lineNum = idx + 1;
            const trimmed = line.trim();

            // 1. Privileged container
            if (/privileged\s*:\s*true/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:compose-privileged-container`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "container-scanner",
                  category: "CONTAINER",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "compose-privileged-container",
                  title: "Privileged Container Enabled in Docker Compose",
                  description: "'privileged: true' gives the container full kernel capabilities and direct access to all host devices, allowing full host system compromise.",
                  codeSnippet: line,
                  secretRef: null,
                  iacPlatform: "docker-compose",
                  complianceStandard: "CIS Docker Benchmark 5.4",
                  scaRemediation: "Set 'privileged: false' and grant only the minimal required Linux capabilities using 'cap_add'.",
                  severity: "critical",
                  cwe: "CWE-250"
                });
              }
            }

            // 2. Unsafe capabilities
            if (/cap_add\s*:\s*\[.*(ALL|SYS_ADMIN|NET_ADMIN|DAC_OVERRIDE|SYS_RAWIO).*\]/i.test(trimmed) || /-\s*(ALL|SYS_ADMIN|NET_ADMIN|DAC_OVERRIDE|SYS_RAWIO)/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:compose-unsafe-capabilities`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "container-scanner",
                  category: "CONTAINER",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "compose-unsafe-capabilities",
                  title: "Dangerous Linux Capability Granted to Container",
                  description: "Adding SYS_ADMIN, ALL, or NET_ADMIN capabilities bypasses kernel isolation boundaries and enables host privilege escalation.",
                  codeSnippet: line,
                  secretRef: null,
                  iacPlatform: "docker-compose",
                  complianceStandard: "CIS Docker Benchmark 5.2",
                  scaRemediation: "Drop all default capabilities with 'cap_drop: [ALL]' and only add specific unprivileged capabilities.",
                  severity: "high",
                  cwe: "CWE-250"
                });
              }
            }

            // 3. Docker socket mount
            if (/\/var\/run\/docker\.sock/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:compose-docker-socket-mount`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "container-scanner",
                  category: "CONTAINER",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "compose-docker-socket-mount",
                  title: "Docker Daemon Socket Mounted into Container (/var/run/docker.sock)",
                  description: "Mounting the host Docker socket into a container allows any process inside the container to command the host Docker daemon, creating an instant root shell on the host.",
                  codeSnippet: line,
                  secretRef: null,
                  iacPlatform: "docker-compose",
                  complianceStandard: "CIS Docker Benchmark 5.31",
                  scaRemediation: "Remove the '/var/run/docker.sock' volume mount. Use Docker API over TLS with client authentication if container orchestration is required.",
                  severity: "critical",
                  cwe: "CWE-250"
                });
              }
            }

            // 4. Host networking / PID / IPC mode
            if (/(?:network_mode|pid|ipc)\s*:\s*["']?host["']?/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:compose-host-namespace-shared`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "container-scanner",
                  category: "CONTAINER",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "compose-host-namespace-shared",
                  title: "Container Shares Host Namespace (Network / PID / IPC)",
                  description: "Sharing host network or PID namespaces disables container network and process isolation, enabling sniffing of host traffic and process tampering.",
                  codeSnippet: line,
                  secretRef: null,
                  iacPlatform: "docker-compose",
                  complianceStandard: "CIS Docker Benchmark 5.9",
                  scaRemediation: "Use bridge network mode ('network_mode: bridge' or custom overlay network) instead of host mode.",
                  severity: "high",
                  cwe: "CWE-693"
                });
              }
            }

            // 5. Exposed secrets in compose environment
            const envSecretMatch = trimmed.match(/(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY|DB_PASS)\s*[:=]\s*["']?([^"'\s$]{4,})["']?/i);
            if (envSecretMatch && !envSecretMatch[1].startsWith("${")) {
              const key = `${relFile}:${lineNum}:compose-plaintext-secret`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "container-scanner",
                  category: "CONTAINER",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "compose-plaintext-secret",
                  title: "Plaintext Secret Defined in Docker Compose Environment",
                  description: "Storing plaintext passwords and API keys in docker-compose.yml risks committing sensitive credentials to source version control.",
                  codeSnippet: maskAllSecretsInText(line),
                  secretRef: null,
                  isMasked: true,
                  iacPlatform: "docker-compose",
                  complianceStandard: "CIS Docker Benchmark 5.14",
                  scaRemediation: "Reference environment variables using variable substitution (e.g. '${DATABASE_PASSWORD}') or Docker Compose secrets.",
                  severity: "critical",
                  cwe: "CWE-798"
                });
              }
            }
          });
        }
      }

      return {
        scanner: "container-scanner",
        status: "success",
        findings,
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        scanner: "container-scanner",
        status: "failed",
        findings: [],
        error: msg,
        executionTimeMs: Date.now() - startTime
      };
    }
  }
}

async function getAllFiles(dir: string, baseDir = dir): Promise<string[]> {
  let results: string[] = [];
  const list = await readdir(dir).catch(() => []);

  for (const file of list) {
    const filePath = path.join(dir, file);
    const relPath = path.relative(baseDir, filePath).replace(/\\/g, "/");

    if (relPath.startsWith("node_modules/") || relPath.startsWith(".git/") || relPath.startsWith("dist/")) {
      continue;
    }

    try {
      const fileStat = await stat(filePath);
      if (fileStat.isDirectory()) {
        const subFiles = await getAllFiles(filePath, baseDir);
        results = results.concat(subFiles);
      } else if (fileStat.isFile()) {
        results.push(relPath);
      }
    } catch {
      // skip
    }
  }

  return results;
}
