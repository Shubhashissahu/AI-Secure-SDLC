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

export class IacScanner implements SecurityScanner {
  readonly name = "iac-scanner" as const;

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: NormalizedFinding[] = [];
    const seenKeys = new Set<string>();

    try {
      // 1. Trivy config for real IaC (Terraform, Kubernetes, CloudFormation) misconfigurations
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
          const isIacTarget =
            target.endsWith(".tf") ||
            target.endsWith(".tfvars") ||
            (target.endsWith(".yaml") && !target.includes("docker-compose") && !target.includes("compose.y")) ||
            (target.endsWith(".yml") && !target.includes("docker-compose") && !target.includes("compose.y"));

          if (isIacTarget && res.Misconfigurations) {
            for (const misconf of res.Misconfigurations) {
              const relFile = path.relative(repoPath, target) || target;
              const ruleId = misconf.ID || misconf.AVDID || "IAC-MISCONFIG";
              const line = misconf.Resolution?.Line || 1;
              const key = `${relFile}:${line}:${ruleId}`;

              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                const sev = mapTrivySeverity(misconf.Severity);
                const title = misconf.Title || misconf.Description || ruleId;
                const remediation = misconf.Resolution || "Follow CIS Benchmark IaC guidelines.";
                const isTf = target.endsWith(".tf") || target.endsWith(".tfvars");

                findings.push({
                  tool: "trivy-config",
                  category: "IAC",
                  file: relFile.replace(/\\/g, "/"),
                  line,
                  ruleId,
                  title,
                  description: misconf.Description || title,
                  codeSnippet: maskAllSecretsInText(
                    `Target: ${relFile}\nIssue: ${title}\nRemediation: ${remediation}\nMessage: ${misconf.Message || ""}`
                  ),
                  secretRef: null,
                  iacPlatform: isTf ? "terraform" : "kubernetes",
                  complianceStandard: isTf ? "CIS Terraform / AWS Benchmark" : "CIS Kubernetes Benchmark",
                  scaRemediation: remediation,
                  severity: sev,
                  cwe: "CWE-16"
                });
              }
            }
          }
        }
      } catch (trivyErr: unknown) {
        console.warn("[IacScanner] Trivy config note:", trivyErr instanceof Error ? trivyErr.message : String(trivyErr));
      }

      // 2. Perform deep static analysis on Terraform and Kubernetes files
      const files = await getAllFiles(repoPath);

      for (const relFile of files) {
        const fullPath = path.join(repoPath, relFile);
        const ext = path.extname(relFile).toLowerCase();

        // ── Terraform Analysis (.tf, .tfvars) ──────────────────────
        if (ext === ".tf" || ext === ".tfvars") {
          const content = await readFile(fullPath, "utf-8").catch(() => "");
          if (!content) continue;

          const lines = content.split("\n");

          lines.forEach((line, idx) => {
            const lineNum = idx + 1;
            const trimmed = line.trim();

            // 1. 0.0.0.0/0 exposure in Security Groups / CIDR
            if (/cidr_blocks\s*=\s*\[.*0\.0\.0\.0\/0.*\]/i.test(trimmed)) {
              // Check surrounding context for sensitive ports
              const surrounding = lines.slice(Math.max(0, idx - 5), Math.min(lines.length, idx + 5)).join("\n");
              const isSensitivePort = /(?:port|from_port|to_port)\s*=\s*(?:22|3389|5432|3306|27017|6379|9200|8080)/i.test(surrounding);

              const key = `${relFile}:${lineNum}:tf-unrestricted-cidr-exposure`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "iac-scanner",
                  category: "IAC",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "tf-unrestricted-cidr-exposure",
                  title: isSensitivePort
                    ? "Critical Port Open to the Public Internet (0.0.0.0/0 Exposure)"
                    : "Security Group Allows Unrestricted Ingress (0.0.0.0/0)",
                  description: "Allowing inbound network traffic from 0.0.0.0/0 exposes internal services and administration ports (SSH/RDP/Databases) to brute-force attacks and internet scanners.",
                  codeSnippet: surrounding || line,
                  secretRef: null,
                  resourceType: "aws_security_group_rule",
                  iacPlatform: "terraform",
                  complianceStandard: "CIS AWS Benchmark 4.1 / 4.2",
                  scaRemediation: "Restrict ingress 'cidr_blocks' to specific corporate VPC IP ranges, bastion hosts, or internal subnets.",
                  severity: isSensitivePort ? "critical" : "high",
                  cwe: "CWE-284"
                });
              }
            }

            // 2. Public S3 Bucket ACL
            if (/acl\s*=\s*["'](public-read|public-read-write)["']/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:tf-s3-public-access`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "iac-scanner",
                  category: "IAC",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "tf-s3-public-access",
                  title: "S3 Bucket Configured with Public Read/Write ACL",
                  description: "Setting S3 bucket ACL to 'public-read' or 'public-read-write' allows unauthorized internet users to access, download, or tamper with stored object data.",
                  codeSnippet: line,
                  secretRef: null,
                  resourceType: "aws_s3_bucket",
                  iacPlatform: "terraform",
                  complianceStandard: "CIS AWS Benchmark 2.1.5",
                  scaRemediation: "Set 'acl = \"private\"' and enable 'aws_s3_bucket_public_access_block' resource with all block flags enabled.",
                  severity: "critical",
                  cwe: "CWE-732"
                });
              }
            }

            // 3. Excessive permissions in IAM ("Action": "*", "Resource": "*", Action = "*")
            if (/(["']?Action["']?\s*[:=]\s*(?:["']\*["']|\[\s*["']\*["']\s*\])|actions\s*=\s*\[\s*["']\*["']\s*\])/i.test(trimmed)) {
              const surrounding = lines.slice(Math.max(0, idx - 6), Math.min(lines.length, idx + 6)).join("\n");
              if (/(["']?Resource["']?\s*[:=]\s*(?:["']\*["']|\[\s*["']\*["']\s*\])|resources\s*=\s*\[\s*["']\*["']\s*\])/i.test(surrounding)) {
                const key = `${relFile}:${lineNum}:tf-iam-wildcard-admin`;
                if (!seenKeys.has(key)) {
                  seenKeys.add(key);
                  findings.push({
                    tool: "iac-scanner",
                    category: "IAC",
                    file: relFile.replace(/\\/g, "/"),
                    line: lineNum,
                    ruleId: "tf-iam-wildcard-admin",
                    title: "Excessive IAM Wildcard Permissions (Full Admin Privilege)",
                    description: "IAM policy grants unrestricted wildcard privileges ('Action: *' on 'Resource: *'), violating least privilege and exposing cloud infrastructure to full takeover.",
                    codeSnippet: surrounding || line,
                    secretRef: null,
                    resourceType: "aws_iam_policy",
                    iacPlatform: "terraform",
                    complianceStandard: "CIS AWS Benchmark 1.16",
                    scaRemediation: "Scope IAM actions to specific API operations (e.g. 's3:GetObject', 'dynamodb:Query') and target specific resource ARNs.",
                    severity: "critical",
                    cwe: "CWE-250"
                  });
                }
              }
            }

            // 4. Exposed secrets in Terraform default variables or tfvars
            const tfSecretMatch = trimmed.match(/(?:default|password|secret_key|api_key|token)\s*=\s*["']([^"'\s$]{6,})["']/i);
            if (tfSecretMatch && !tfSecretMatch[1].startsWith("${")) {
              const key = `${relFile}:${lineNum}:tf-hardcoded-secret`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "iac-scanner",
                  category: "IAC",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "tf-hardcoded-secret",
                  title: "Hardcoded Credential or Secret in Terraform Configuration",
                  description: "Terraform configuration contains static plaintext passwords or secret tokens in default attributes or tfvars.",
                  codeSnippet: maskAllSecretsInText(line),
                  secretRef: null,
                  isMasked: true,
                  iacPlatform: "terraform",
                  complianceStandard: "CIS Terraform Benchmark 1.1",
                  scaRemediation: "Retrieve sensitive secrets dynamically using AWS Secrets Manager, HashiCorp Vault, or environment variables (TF_VAR_...).",
                  severity: "critical",
                  cwe: "CWE-798"
                });
              }
            }

            // 5. Unencrypted S3 storage or EBS volumes
            if (/encrypted\s*=\s*false/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:tf-unencrypted-storage`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "iac-scanner",
                  category: "IAC",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "tf-unencrypted-storage",
                  title: "Storage Volume Explicitly Configured Without Encryption",
                  description: "EBS storage or database volume has encryption disabled, allowing data exposure if raw storage media is inspected.",
                  codeSnippet: line,
                  secretRef: null,
                  resourceType: "aws_ebs_volume",
                  iacPlatform: "terraform",
                  complianceStandard: "CIS AWS Benchmark 2.2.1",
                  scaRemediation: "Set 'encrypted = true' and specify a customer-managed or AWS KMS key.",
                  severity: "high",
                  cwe: "CWE-311"
                });
              }
            }
          });
        }

        // ── Kubernetes Manifest Analysis (*.yaml, *.yml) ─────────
        else if (
          (ext === ".yaml" || ext === ".yml") &&
          !relFile.toLowerCase().includes("docker-compose") &&
          !relFile.toLowerCase().includes("compose.y")
        ) {
          const content = await readFile(fullPath, "utf-8").catch(() => "");
          if (!content) continue;

          // Check if file is a Kubernetes manifest
          const isK8s =
            /apiVersion\s*:\s*(?:v1|apps\/v1|batch\/v1|rbac\.authorization\.k8s\.io)/i.test(content) ||
            /kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|Job|ClusterRoleBinding|ConfigMap)/i.test(content);

          if (!isK8s) continue;

          const lines = content.split("\n");

          lines.forEach((line, idx) => {
            const lineNum = idx + 1;
            const trimmed = line.trim();

            // 1. Privileged container in K8s
            if (/privileged\s*:\s*true/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:k8s-privileged-container`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "iac-scanner",
                  category: "IAC",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "k8s-privileged-container",
                  title: "Kubernetes Pod Configured with Privileged Container",
                  description: "'securityContext.privileged: true' grants container processes access to host devices and capabilities, disabling container sandbox isolation.",
                  codeSnippet: line,
                  secretRef: null,
                  resourceType: "Kubernetes Pod / SecurityContext",
                  iacPlatform: "kubernetes",
                  complianceStandard: "CIS Kubernetes Benchmark 5.2.1",
                  scaRemediation: "Set 'securityContext.privileged: false' and drop all unnecessary capabilities.",
                  severity: "critical",
                  cwe: "CWE-250"
                });
              }
            }

            // 2. Root execution in K8s
            if (/runAsNonRoot\s*:\s*false/i.test(trimmed) || /runAsUser\s*:\s*0\b/i.test(trimmed)) {
              const key = `${relFile}:${lineNum}:k8s-run-as-root`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "iac-scanner",
                  category: "IAC",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "k8s-run-as-root",
                  title: "Kubernetes Container Configured to Run as Root",
                  description: "Container is explicitly configured with 'runAsNonRoot: false' or 'runAsUser: 0', allowing container processes to run as root.",
                  codeSnippet: line,
                  secretRef: null,
                  resourceType: "Kubernetes Pod / SecurityContext",
                  iacPlatform: "kubernetes",
                  complianceStandard: "CIS Kubernetes Benchmark 5.2.6",
                  scaRemediation: "Set 'securityContext.runAsNonRoot: true' and define 'runAsUser: 10001'.",
                  severity: "high",
                  cwe: "CWE-250"
                });
              }
            }

            // 3. ClusterRoleBinding to cluster-admin for default SA
            if (/name\s*:\s*cluster-admin/i.test(trimmed)) {
              const surrounding = lines.slice(Math.max(0, idx - 5), Math.min(lines.length, idx + 5)).join("\n");
              if (/kind\s*:\s*ClusterRoleBinding/i.test(content) && /default/i.test(surrounding)) {
                const key = `${relFile}:${lineNum}:k8s-cluster-admin-default-sa`;
                if (!seenKeys.has(key)) {
                  seenKeys.add(key);
                  findings.push({
                    tool: "iac-scanner",
                    category: "IAC",
                    file: relFile.replace(/\\/g, "/"),
                    line: lineNum,
                    ruleId: "k8s-cluster-admin-default-sa",
                    title: "Kubernetes ClusterRoleBinding Grants cluster-admin to Default ServiceAccount",
                    description: "Binding 'cluster-admin' to the default serviceaccount gives any unprivileged pod in the namespace complete control over the entire Kubernetes cluster.",
                    codeSnippet: surrounding || line,
                    secretRef: null,
                    resourceType: "ClusterRoleBinding",
                    iacPlatform: "kubernetes",
                    complianceStandard: "CIS Kubernetes Benchmark 5.1.1",
                    scaRemediation: "Create dedicated ServiceAccounts with fine-grained Roles bound via RoleBindings scoped to specific namespaces.",
                    severity: "critical",
                    cwe: "CWE-250"
                  });
                }
              }
            }

            // 4. Insecure HostPath volume mount
            if (/hostPath\s*:/i.test(trimmed)) {
              const surrounding = lines.slice(Math.max(0, idx - 2), Math.min(lines.length, idx + 4)).join("\n");
              const key = `${relFile}:${lineNum}:k8s-hostpath-mount`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "iac-scanner",
                  category: "IAC",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "k8s-hostpath-mount",
                  title: "Kubernetes Volume Mounts Host Filesystem (hostPath)",
                  description: "Mounting host directories into pods enables container processes to read or overwrite critical host filesystem files, bypassing container boundaries.",
                  codeSnippet: surrounding || line,
                  secretRef: null,
                  resourceType: "Kubernetes Pod / Volume",
                  iacPlatform: "kubernetes",
                  complianceStandard: "CIS Kubernetes Benchmark 5.2.4",
                  scaRemediation: "Use PersistentVolumeClaims (PVC) backed by cloud storage or emptyDir instead of raw hostPath mounts.",
                  severity: "high",
                  cwe: "CWE-552"
                });
              }
            }

            // 5. Plaintext secret stored in ConfigMap instead of Secret
            if (/kind\s*:\s*ConfigMap/i.test(content)) {
              const secretMatch = trimmed.match(/(?:password|api_key|secret|token|private_key)\s*:\s*["']?([^"'\s$]{5,})["']?/i);
              if (secretMatch) {
                const key = `${relFile}:${lineNum}:k8s-secret-in-configmap`;
                if (!seenKeys.has(key)) {
                  seenKeys.add(key);
                  findings.push({
                    tool: "iac-scanner",
                    category: "IAC",
                    file: relFile.replace(/\\/g, "/"),
                    line: lineNum,
                    ruleId: "k8s-secret-in-configmap",
                    title: "Sensitive Secret or Password Stored in Plaintext Kubernetes ConfigMap",
                    description: "ConfigMaps are unencrypted and visible to all namespace users. Passwords and credentials must be stored in Kubernetes Secrets with encryption at rest.",
                    codeSnippet: maskAllSecretsInText(line),
                    secretRef: null,
                    isMasked: true,
                    resourceType: "ConfigMap",
                    iacPlatform: "kubernetes",
                    complianceStandard: "CIS Kubernetes Benchmark 5.4.1",
                    scaRemediation: "Migrate the credential to a Kubernetes Secret resource or integrate with HashiCorp Vault / External Secrets Operator.",
                    severity: "critical",
                    cwe: "CWE-798"
                  });
                }
              }
            }
          });
        }
      }

      return {
        scanner: "iac-scanner",
        status: "success",
        findings,
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        scanner: "iac-scanner",
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
