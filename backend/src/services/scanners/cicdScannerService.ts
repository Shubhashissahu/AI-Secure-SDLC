import { readFile, readdir } from "fs/promises";
import path from "path";
import { SecurityScanner, ScannerResult } from "./SecurityScanner";
import { NormalizedFinding } from "./types";
import { maskAllSecretsInText } from "../../utils/secretMasker";

export class CicdScanner implements SecurityScanner {
  readonly name = "cicd-scanner" as const;

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: NormalizedFinding[] = [];
    const seenKeys = new Set<string>();

    try {
      const workflowFiles = await findWorkflowFiles(repoPath);

      for (const relFile of workflowFiles) {
        const fullPath = path.join(repoPath, relFile);
        const content = await readFile(fullPath, "utf-8").catch(() => "");
        if (!content) continue;

        const lines = content.split("\n");

        // Extract workflow name
        const nameMatch = content.match(/^name\s*:\s*["']?([^"'\r\n]+)["']?/m);
        const workflowName = nameMatch ? nameMatch[1].trim() : path.basename(relFile, path.extname(relFile));

        const hasExplicitPermissions = /^\s*permissions\s*:/m.test(content);
        const isPullRequestTarget = /pull_request_target/i.test(content);

        // 1. Dangerous pull_request_target with untrusted checkout
        if (isPullRequestTarget && (content.includes("pull_request.head.sha") || content.includes("github.head_ref"))) {
          const targetLineIdx = lines.findIndex((l) => l.includes("pull_request_target") || l.includes("pull_request.head.sha"));
          const lineNum = targetLineIdx >= 0 ? targetLineIdx + 1 : 1;
          const key = `${relFile}:${lineNum}:cicd-dangerous-pull-request-target`;

          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            findings.push({
              tool: "cicd-scanner",
              category: "CI_CD",
              file: relFile.replace(/\\/g, "/"),
              line: lineNum,
              ruleId: "cicd-dangerous-pull-request-target",
              workflowName,
              title: "Dangerous 'pull_request_target' Trigger with Untrusted PR Code Checkout",
              description: "The workflow triggers on 'pull_request_target' (which runs in the context of the base repository with repository secrets and write tokens) while checking out untrusted code from the pull request head. Malicious PRs can compromise repository secrets and push arbitrary code.",
              codeSnippet: lines.slice(Math.max(0, lineNum - 3), Math.min(lines.length, lineNum + 4)).join("\n"),
              secretRef: null,
              complianceStandard: "CIS GitHub Actions Benchmark 1.1 / OpenSSF Scorecard",
              scaRemediation: "Switch trigger to 'pull_request' or avoid checking out PR head code in 'pull_request_target'. If building artifacts is required, split the workflow into an unprivileged build job and a separate artifact upload job.",
              severity: "critical",
              cwe: "CWE-94"
            });
          }
        }

        // 2. Missing permissions restrictions across workflow
        if (!hasExplicitPermissions && lines.length > 5) {
          const key = `${relFile}:1:cicd-missing-permissions-block`;
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            findings.push({
              tool: "cicd-scanner",
              category: "CI_CD",
              file: relFile.replace(/\\/g, "/"),
              line: 1,
              ruleId: "cicd-missing-permissions-block",
              workflowName,
              title: "Workflow Missing Explicit Least-Privilege 'permissions' Block",
              description: "Workflow does not specify an explicit top-level 'permissions:' block. By default, the GITHUB_TOKEN may inherit write access to repository contents, packages, issues, and deployments.",
              codeSnippet: lines.slice(0, 5).join("\n"),
              secretRef: null,
              complianceStandard: "CIS GitHub Actions Benchmark 1.2",
              scaRemediation: "Add a top-level 'permissions: contents: read' (or 'permissions: {}') to enforce least privilege for GITHUB_TOKEN.",
              severity: "high",
              cwe: "CWE-250"
            });
          }
        }

        let inRunBlock = false;

        // Line-by-line inspection
        lines.forEach((line, idx) => {
          const lineNum = idx + 1;
          const trimmed = line.trim();

          if (/^\s*run\s*:\s*\|/i.test(line)) {
            inRunBlock = true;
          } else if (/^\s*(-\s*name|uses|with|env|id|if|steps):/i.test(line)) {
            inRunBlock = false;
          }

          // 3. Command Injection via untrusted expression interpolation in run:
          const isRunContext = inRunBlock || /run\s*:/i.test(trimmed);
          const exprMatch = trimmed.match(/\$\{\{\s*(github\.event\.(?:issue|pull_request|comment|head_commit|review|release)\.[a-zA-Z0-9_.]+|github\.head_ref)\s*\}\}/i);

          if (isRunContext && exprMatch) {
            const injectedVar = exprMatch[1];
            const key = `${relFile}:${lineNum}:cicd-expression-command-injection`;
            if (!seenKeys.has(key)) {
              seenKeys.add(key);
              findings.push({
                tool: "cicd-scanner",
                category: "CI_CD",
                file: relFile.replace(/\\/g, "/"),
                line: lineNum,
                ruleId: "cicd-expression-command-injection",
                workflowName,
                title: `Command Injection via Inline Expression (${injectedVar})`,
                description: `Interpolating user-controlled GitHub context '${injectedVar}' directly inside a 'run:' shell command allows attackers to execute arbitrary shell commands via quotes and shell metacharacters in PR titles, issue bodies, or branch names.`,
                codeSnippet: line,
                secretRef: null,
                complianceStandard: "CIS GitHub Actions Benchmark 1.3 / CWE-78",
                scaRemediation: `Pass '${injectedVar}' via an environment variable in the step's 'env:' block and reference it as a shell variable (e.g. '$PR_TITLE') instead of inline '\${{ ... }}'.`,
                severity: "critical",
                cwe: "CWE-78"
              });
            }
          }

          // 4. Excessive Permissions (write-all)
          if (/permissions\s*:\s*["']?write-all["']?/i.test(trimmed)) {
            const key = `${relFile}:${lineNum}:cicd-excessive-permissions-write-all`;
            if (!seenKeys.has(key)) {
              seenKeys.add(key);
              findings.push({
                tool: "cicd-scanner",
                category: "CI_CD",
                file: relFile.replace(/\\/g, "/"),
                line: lineNum,
                ruleId: "cicd-excessive-permissions-write-all",
                workflowName,
                title: "Excessive Permissions: 'permissions: write-all' Configured",
                description: "'permissions: write-all' grants maximum read and write privileges across all GitHub scopes (actions, checks, contents, deployments, issues, packages, pull-requests, security-events), violating the principle of least privilege.",
                codeSnippet: line,
                secretRef: null,
                complianceStandard: "CIS GitHub Actions Benchmark 1.2",
                scaRemediation: "Replace 'write-all' with explicit minimal required permissions (e.g. 'contents: read', 'pull-requests: write').",
                severity: "critical",
                cwe: "CWE-250"
              });
            }
          }

          // 5. Secrets Exposure in echo / print
          if (/run\s*:.*echo\s+["']?.*?\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}/i.test(trimmed)) {
            const key = `${relFile}:${lineNum}:cicd-secret-exposure-echo`;
            if (!seenKeys.has(key)) {
              seenKeys.add(key);
              findings.push({
                tool: "cicd-scanner",
                category: "CI_CD",
                file: relFile.replace(/\\/g, "/"),
                line: lineNum,
                ruleId: "cicd-secret-exposure-echo",
                workflowName,
                title: "Sensitive GitHub Secret Printed in Workflow Execution Logs",
                description: "Printing secret variables directly in 'run: echo ${{ secrets... }}' exposes sensitive API keys and tokens in workflow run logs and build artifacts.",
                codeSnippet: maskAllSecretsInText(line),
                secretRef: null,
                isMasked: true,
                complianceStandard: "CIS GitHub Actions Benchmark 1.4",
                scaRemediation: "Never print secret values to standard output. Use secret masking or pass secrets directly to target commands via environment variables.",
                severity: "critical",
                cwe: "CWE-798"
              });
            }
          }

          // 6. Mutable Action Tags (uses: ...@v1, @v2, @main, @master)
          const usesMatch = trimmed.match(/uses\s*:\s*([a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+)@([a-zA-Z0-9_.-]+)/i);
          if (usesMatch) {
            const actionRef = usesMatch[1];
            const actionVersion = usesMatch[2];
            const isFullSha = /^[0-9a-f]{40}$/i.test(actionVersion);

            // Skip local actions (./.github/actions/...)
            if (!actionRef.startsWith(".") && !isFullSha) {
              const key = `${relFile}:${lineNum}:cicd-mutable-action-tag`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "cicd-scanner",
                  category: "CI_CD",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "cicd-mutable-action-tag",
                  workflowName,
                  actionName: actionRef,
                  title: `Action Pinned to Mutable Tag or Branch (@${actionVersion})`,
                  description: `Action '${actionRef}' is referenced using mutable tag or branch '@${actionVersion}' instead of an immutable 40-character commit SHA. If the action repository is compromised, attackers can overwrite the tag with malicious code.`,
                  codeSnippet: line,
                  secretRef: null,
                  complianceStandard: "CIS GitHub Actions Benchmark 1.5 / OpenSSF Scorecard",
                  scaRemediation: `Pin the action to an immutable full commit SHA (e.g. 'uses: ${actionRef}@<commit-sha> # ${actionVersion}').`,
                  severity: "medium",
                  cwe: "CWE-1395"
                });
              }
            }

            // 7. Unsafe / Unverified third-party actions
            const isKnownOrg = /^(actions|github|docker|aws-actions|google-github-actions|azure|hashicorp)\//i.test(actionRef);
            if (!isKnownOrg && !actionRef.startsWith(".")) {
              const key = `${relFile}:${lineNum}:cicd-unverified-third-party-action`;
              if (!seenKeys.has(key)) {
                seenKeys.add(key);
                findings.push({
                  tool: "cicd-scanner",
                  category: "CI_CD",
                  file: relFile.replace(/\\/g, "/"),
                  line: lineNum,
                  ruleId: "cicd-unverified-third-party-action",
                  workflowName,
                  actionName: actionRef,
                  title: `Unverified Third-Party Action Used in Pipeline (${actionRef})`,
                  description: `Using unverified third-party action '${actionRef}' introduces supply chain risk. Third-party actions have full execution access to the workflow runner environment and secrets.`,
                  codeSnippet: line,
                  secretRef: null,
                  complianceStandard: "CIS GitHub Actions Benchmark 1.6",
                  scaRemediation: "Review the source code of third-party actions, verify creator reputation, pin to immutable commit SHA, and consider internal vendoring.",
                  severity: "low",
                  cwe: "CWE-1395"
                });
              }
            }
          }
        });
      }

      return {
        scanner: "cicd-scanner",
        status: "success",
        findings,
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        scanner: "cicd-scanner",
        status: "failed",
        findings: [],
        error: msg,
        executionTimeMs: Date.now() - startTime
      };
    }
  }
}

async function findWorkflowFiles(dir: string): Promise<string[]> {
  const workflowsDir = path.join(dir, ".github", "workflows");
  const results: string[] = [];

  try {
    const list = await readdir(workflowsDir).catch(() => []);
    for (const file of list) {
      const ext = path.extname(file).toLowerCase();
      if (ext === ".yml" || ext === ".yaml") {
        results.push(`.github/workflows/${file}`);
      }
    }
  } catch {
    // skip
  }

  // Also check if any yml/yaml files exist under other workflow-like paths
  return results;
}
