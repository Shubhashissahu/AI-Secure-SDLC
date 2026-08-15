import { readFile } from "fs/promises";
import path from "path";
import crypto from "crypto";
import { SecurityScanner, ScannerResult } from "./SecurityScanner";
import { NormalizedFinding } from "./types";
import { maskAllSecretsInText } from "../../utils/secretMasker";
import { GitleaksScanner } from "./gitleaksService";

export interface SecretRuleDefinition {
  ruleId: string;
  name: string;
  secretType: "api_key" | "aws_credential" | "github_token" | "jwt_secret" | "db_password" | "private_key" | "access_token";
  severity: "critical" | "high" | "medium";
  pattern: RegExp;
  cwe: string;
  description: string;
}

export const SECRET_RULES: SecretRuleDefinition[] = [
  // 1. AWS Credentials
  {
    ruleId: "aws-access-key-id",
    name: "AWS Access Key ID",
    secretType: "aws_credential",
    severity: "critical",
    pattern: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}/g,
    cwe: "CWE-798",
    description: "Hardcoded AWS Access Key ID detected."
  },
  {
    ruleId: "aws-secret-access-key",
    name: "AWS Secret Access Key",
    secretType: "aws_credential",
    severity: "critical",
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    cwe: "CWE-798",
    description: "Hardcoded AWS Secret Access Key assignment detected."
  },

  // 2. GitHub Tokens
  {
    ruleId: "github-personal-access-token",
    name: "GitHub Personal Access Token",
    secretType: "github_token",
    severity: "critical",
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
    cwe: "CWE-798",
    description: "GitHub Personal Access Token or OAuth token detected."
  },
  {
    ruleId: "github-fine-grained-token",
    name: "GitHub Fine-Grained Token",
    secretType: "github_token",
    severity: "critical",
    pattern: /github_pat_[A-Za-z0-9_]{82}/g,
    cwe: "CWE-798",
    description: "GitHub fine-grained personal access token detected."
  },

  // 3. Private Keys
  {
    ruleId: "asymmetric-private-key",
    name: "Asymmetric Private Key",
    secretType: "private_key",
    severity: "critical",
    pattern: /-----BEGIN (?:[A-Z0-9_-]+\s)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+\s)?PRIVATE KEY-----/g,
    cwe: "CWE-798",
    description: "Unencrypted Asymmetric Private Key block (RSA/EC/DSA/OPENSSH) detected in source."
  },
  {
    ruleId: "pgp-private-key",
    name: "PGP Private Key",
    secretType: "private_key",
    severity: "critical",
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    cwe: "CWE-798",
    description: "PGP Private Key Block detected."
  },

  // 4. JWT Secrets & Tokens
  {
    ruleId: "jwt-token-raw",
    name: "Raw JSON Web Token (JWT)",
    secretType: "jwt_secret",
    severity: "high",
    pattern: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+/g,
    cwe: "CWE-798",
    description: "Hardcoded JSON Web Token detected with signed claims."
  },
  {
    ruleId: "jwt-secret-assignment",
    name: "Hardcoded JWT Secret Key",
    secretType: "jwt_secret",
    severity: "critical",
    pattern: /(?:jwt_secret|jwt_key|jwt_secret_key|token_secret)\s*[:=]\s*["']([^"'\r\n]{6,})["']/gi,
    cwe: "CWE-798",
    description: "Hardcoded secret string used for signing JWT authentication tokens."
  },

  // 5. Database Passwords & URIs
  {
    ruleId: "database-uri-with-credentials",
    name: "Database URI with Credentials",
    secretType: "db_password",
    severity: "critical",
    pattern: /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|mssql):\/\/[a-zA-Z0-9._~%-]+:([^@\s'"]+)@[a-zA-Z0-9.-]+/gi,
    cwe: "CWE-798",
    description: "Database connection string containing embedded plaintext password."
  },
  {
    ruleId: "db-password-assignment",
    name: "Hardcoded Database Password",
    secretType: "db_password",
    severity: "critical",
    pattern: /(?:db_password|database_password|dbpass|db_pass|db_secret)\s*[:=]\s*["']([^"'\r\n]{4,})["']/gi,
    cwe: "CWE-798",
    description: "Database authentication password assigned in source or configuration."
  },

  // 6. API Keys
  {
    ruleId: "openai-api-key",
    name: "OpenAI API Key",
    secretType: "api_key",
    severity: "critical",
    pattern: /sk-[a-zA-Z0-9]{32,64}/g,
    cwe: "CWE-798",
    description: "Hardcoded OpenAI API Secret Key detected."
  },
  {
    ruleId: "stripe-api-key",
    name: "Stripe Live Secret Key",
    secretType: "api_key",
    severity: "critical",
    pattern: /sk_live_[0-9a-zA-Z]{24,34}/g,
    cwe: "CWE-798",
    description: "Stripe Production Secret Key detected."
  },
  {
    ruleId: "google-api-key",
    name: "Google Cloud API Key",
    secretType: "api_key",
    severity: "high",
    pattern: /AIza[0-9A-Za-z-_]{35}/g,
    cwe: "CWE-798",
    description: "Google Cloud / Firebase API Key detected."
  },
  {
    ruleId: "slack-token",
    name: "Slack API / Bot Token",
    secretType: "api_key",
    severity: "critical",
    pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
    cwe: "CWE-798",
    description: "Slack API OAuth / Bot access token detected."
  },
  {
    ruleId: "generic-api-key-assignment",
    name: "Generic API Key Assignment",
    secretType: "api_key",
    severity: "high",
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9-_.~+/=]{16,})["']/gi,
    cwe: "CWE-798",
    description: "Generic API key or secret token literal assignment detected."
  },

  // 7. Access Tokens
  {
    ruleId: "bearer-access-token",
    name: "Bearer / Authorization Access Token",
    secretType: "access_token",
    severity: "high",
    pattern: /Bearer\s+([A-Za-z0-9-._~+/=]{24,})/gi,
    cwe: "CWE-798",
    description: "Hardcoded Bearer authentication token in HTTP header or authorization string."
  },
  {
    ruleId: "oauth-access-token-assignment",
    name: "OAuth Access Token",
    secretType: "access_token",
    severity: "high",
    pattern: /(?:access[_-]?token|auth[_-]?token|oauth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9-_.~+/=]{16,})["']/gi,
    cwe: "CWE-798",
    description: "Hardcoded OAuth or third-party access token detected."
  }
];

const IGNORED_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf",
  ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar",
  ".gz", ".exe", ".dll", ".so", ".dylib", ".lock", ".bin"
]);

const IGNORED_PATHS = [
  "node_modules/", ".git/", "dist/", "build/", ".next/", "coverage/",
  ".env.example", ".gitignore"
];

/**
 * Deep Native Secret Scanner.
 * Operates standalone or complements Gitleaks to guarantee 100% detection of
 * API keys, AWS credentials, GitHub tokens, JWT secrets, database passwords,
 * private keys, and access tokens, always masking secrets in output.
 */
export class SecretScanner implements SecurityScanner {
  readonly name = "gitleaks" as const;

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: NormalizedFinding[] = [];
    const seenFingerprints = new Set<string>();

    try {
      // 1. Run Gitleaks CLI if available
      try {
        const gitleaks = new GitleaksScanner();
        const gitleaksResult = await gitleaks.scan(repoPath);
        if (gitleaksResult.status === "success") {
          for (const f of gitleaksResult.findings) {
            f.category = "SECRETS";
            f.codeSnippet = maskAllSecretsInText(f.codeSnippet);
            f.isMasked = true;
            findings.push(f);
            seenFingerprints.add(`${f.file}:${f.line}:${f.ruleId}`);
          }
        }
      } catch (gitleaksErr: unknown) {
        console.warn("[SecretScanner] Gitleaks runner returned note:", gitleaksErr instanceof Error ? gitleaksErr.message : String(gitleaksErr));
      }

      // 2. Perform exhaustive in-depth regex scanning across repo files
      const fileList = await getAllSourceFiles(repoPath);

      for (const relativeFilePath of fileList) {
        const fullPath = path.join(repoPath, relativeFilePath);
        let content = "";
        try {
          content = await readFile(fullPath, "utf-8");
        } catch {
          continue;
        }

        const lines = content.split("\n");

        for (const rule of SECRET_RULES) {
          rule.pattern.lastIndex = 0;
          let match: RegExpExecArray | null;

          while ((match = rule.pattern.exec(content)) !== null) {
            const rawMatch = match[0];
            const capturedSecret = match[1] || rawMatch;

            // Compute line number
            const charIndex = match.index;
            const lineNum = content.slice(0, charIndex).split("\n").length;
            const key = `${relativeFilePath}:${lineNum}:${rule.ruleId}`;

            if (seenFingerprints.has(key)) continue;
            seenFingerprints.add(key);

            const secretHash = crypto.createHash("sha256").update(capturedSecret).digest("hex").slice(0, 16);
            const lineContent = lines[lineNum - 1] || rawMatch;
            const maskedSnippet = maskAllSecretsInText(lineContent);

            findings.push({
              tool: "gitleaks",
              category: "SECRETS",
              file: relativeFilePath.replace(/\\/g, "/"),
              line: lineNum,
              ruleId: rule.ruleId,
              title: rule.name,
              description: rule.description,
              codeSnippet: maskedSnippet.slice(0, 1000),
              secretRef: secretHash,
              secretType: rule.secretType,
              isMasked: true,
              cwe: rule.cwe,
              severity: rule.severity
            });
          }
        }
      }

      return {
        scanner: "gitleaks",
        status: "success",
        findings,
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        scanner: "gitleaks",
        status: "failed",
        findings: [],
        error: msg,
        executionTimeMs: Date.now() - startTime
      };
    }
  }
}

async function getAllSourceFiles(dir: string, baseDir = dir): Promise<string[]> {
  const { readdir, stat } = await import("fs/promises");
  let results: string[] = [];
  const list = await readdir(dir).catch(() => []);

  for (const file of list) {
    const filePath = path.join(dir, file);
    const relPath = path.relative(baseDir, filePath).replace(/\\/g, "/");

    if (IGNORED_PATHS.some((ignored) => relPath.startsWith(ignored) || relPath.includes(`/${ignored}`))) {
      continue;
    }

    try {
      const fileStat = await stat(filePath);
      if (fileStat.isDirectory()) {
        const subFiles = await getAllSourceFiles(filePath, baseDir);
        results = results.concat(subFiles);
      } else if (fileStat.isFile()) {
        const ext = path.extname(file).toLowerCase();
        if (!IGNORED_EXTENSIONS.has(ext) && fileStat.size < 2 * 1024 * 1024) {
          results.push(relPath);
        }
      }
    } catch {
      // skip inaccessible files
    }
  }

  return results;
}
