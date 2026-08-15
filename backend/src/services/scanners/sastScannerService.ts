import path from "path";
import { promises as fs } from "fs";
import { SecurityScanner, ScannerResult } from "./SecurityScanner";
import { NormalizedFinding } from "./types";
import { SemgrepScanner } from "./semgrepService";

interface SastRule {
  id: string;
  name: string;
  cwe: string;
  owasp: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  fileExtensions: string[];
  patterns: RegExp[];
  negativePatterns?: RegExp[];
}

const SAST_RULES: SastRule[] = [
  // 1. SQL Injection (CWE-89)
  {
    id: "sast-sql-injection",
    name: "SQL Injection",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    severity: "high",
    description: "Untrusted user input concatenated directly into SQL statement or query executor.",
    fileExtensions: [".java", ".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".go", ".cs"],
    patterns: [
      // Java - Statement execution with concatenated variables or direct concatenation
      /(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*(?:["'].*?["']\s*\+|String\.format\s*\(\s*["']SELECT|["']SELECT.*?\+\s*[a-zA-Z0-9_]+|[a-zA-Z0-9_]+Query|[a-zA-Z0-9_]+Sql|sql|query)/i,
      /(?:Statement|PreparedStatement|conn|connection|stmt)\s*\.\s*(?:executeQuery|executeUpdate|execute)\s*\(\s*.*?\+/i,
      /String\s+(?:query|sql|sqlQuery|queryString)\s*=\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*\+\s*[a-zA-Z0-9_.]+/i,
      /String\s+(?:query|sql|sqlQuery|queryString)\s*=\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[\s\S]*?\+\s*[a-zA-Z0-9_.]+/i,
      /["']SELECT\s+.*?\s+FROM\s+.*?WHERE\s+.*?=\s*['"]?\s*\+\s*[a-zA-Z0-9_.]+/i,
      /["'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?["']\s*\+\s*[a-zA-Z0-9_.]+/i,
      // Node.js
      /(?:db|client|pool|connection|sequelize|knex)\.query\s*\(\s*`.*?SELECT.*?\$\{.*?`\s*\)/i,
      /(?:db|client|pool|connection|sequelize|knex)\.query\s*\(\s*["'].*?SELECT.*?["']\s*\+\s*[a-zA-Z0-9_.]+/i,
      /knex\.raw\s*\(\s*`.*?\$\{.*?`\s*\)/i,
      // Python
      /(?:cursor|db\.session|connection)\.execute\s*\(\s*f["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}/i,
      /(?:cursor|db\.session|connection)\.execute\s*\(\s*["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*[\+%]\s*[a-zA-Z0-9_.]+/i
    ]
  },

  // 2. Command Injection (CWE-78)
  {
    id: "command-injection",
    name: "Command Injection",
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    severity: "high",
    description: "User-controlled input is passed directly to system shell execution.",
    fileExtensions: [".java", ".js", ".ts", ".py", ".php", ".go", ".cs"],
    patterns: [
      // Java
      /Runtime\.getRuntime\(\)\.exec\s*\(/i,
      /new\s+ProcessBuilder\s*\(/i,
      /ProcessBuilder\s*\(/i,
      // Node.js
      /(?:exec|execSync)\s*\(\s*(?:`.*?\$\{.*?`|["'].*?["']\s*\+|[a-zA-Z0-9_.]+\s*\+)/i,
      /spawn\s*\(\s*.*?,\s*\{.*?shell\s*:\s*true/i,
      // Python
      /os\.(?:system|popen)\s*\(\s*(?:f["'].*?\{.*?\}|["'].*?["']\s*\+|[a-zA-Z0-9_.]+\s*\+)/i,
      /subprocess\.(?:Popen|run|call|check_output)\s*\(\s*(?:f["'].*?\{.*?\}|["'].*?["']\s*\+|[a-zA-Z0-9_.]+\s*\+).*?shell\s*=\s*True/i,
      /subprocess\.(?:Popen|run|call|check_output)\s*\(\s*.*?shell\s*=\s*True/i
    ]
  },

  // 3. Cross-Site Scripting (XSS) (CWE-79)
  {
    id: "xss",
    name: "Cross-Site Scripting (XSS)",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    severity: "high",
    description: "Unsanitized user-controlled input rendered directly into HTTP response or DOM.",
    fileExtensions: [".js", ".ts", ".jsx", ".tsx", ".java", ".py", ".php", ".html"],
    patterns: [
      // Node / Express
      /res\.(?:send|write)\s*\(\s*(?:req\.(?:query|body|params)|userInput|[a-zA-Z0-9_.]*input|[a-zA-Z0-9_.]*content)/i,
      /res\.(?:send|write)\s*\(\s*["'].*?<.*?>.*?["']\s*\+\s*[a-zA-Z0-9_.]+/i,
      /res\.(?:send|write)\s*\(\s*`.*?<.*?>.*?\$\{.*?`\s*\)/i,
      /res\.(?:send|write)\s*\(\s*.*?(?:req\.query|req\.body|req\.params)/i,
      /innerHTML\s*=\s*(?:["'].*?["']\s*\+|req\.(?:query|body)|userInput|[a-zA-Z0-9_.]*\+)/i,
      /innerHTML\s*=\s*[a-zA-Z0-9_.]+/i,
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:req\.|userInput|[a-zA-Z0-9_.]+)/i,
      /document\.write\s*\(/i,
      // Java Servlets
      /response\.getWriter\(\)\.(?:write|print|println)\s*\(\s*(?:request\.getParameter|[a-zA-Z0-9_]+\s*\+|[a-zA-Z0-9_]+)/i,
      // Python Flask / Django
      /render_template_string\s*\(\s*(?:f["'].*?\{.*?\}|["'].*?["']\s*\+)/i,
      /HttpResponse\s*\(\s*(?:f["'].*?\{.*?\}|["'].*?["']\s*\+\s*request\.)/i
    ]
  },

  // 4. Insecure Authentication & Authorization (CWE-287 / CWE-384)
  {
    id: "weak-authentication",
    name: "Insecure Authentication / Broken Access Control",
    cwe: "CWE-287",
    owasp: "A07:2021 - Identification and Authentication Failures",
    severity: "high",
    description: "Flawed authentication logic, plain text password check, hardcoded credentials check, bypassed token validation, or insecure cookie flags detected.",
    fileExtensions: [".java", ".js", ".ts", ".py", ".php"],
    patterns: [
      // Plain text passwords / Hardcoded login check
      /(?:password|pass|passwd)\s*===?\s*["'][a-zA-Z0-9_!@#$%^&*]+["']/i,
      /(?:password|pass|passwd)\.equals\s*\(\s*["'][a-zA-Z0-9_!@#$%^&*]+["']\s*\)/i,
      /if\s*\(\s*(?:password|pass|token|auth)\s*===?\s*["'][a-zA-Z0-9_!@#$%^&*]+["']\s*\)/i,
      /if\s*\(\s*(?:username|user)\s*===?\s*["']admin["']\s*&&\s*password\s*===?\s*["'].*?["']\s*\)/i,
      /if\s*\(\s*req\.body\.password\s*===?\s*["'].*?["']\s*\)/i,
      /if\s*\(\s*username\s*===?\s*["']admin["']\s*\)/i,
      // Hardcoded tokens
      /(?:authToken|bearerToken|accessToken|secretToken)\s*===?\s*["'][a-zA-Z0-9_-]+["']/i,
      // Insecure JWT
      /jwt\.verify\s*\(\s*token\s*,\s*["'](?:none|secret|test|123456|dev)["']/i,
      /jwt\.sign\s*\(\s*.*?algorithm\s*:\s*["']none["']/i,
      // Insecure Cookie
      /res\.cookie\s*\(\s*["'].*?["']\s*,\s*.*?(?:httpOnly\s*:\s*false|secure\s*:\s*false)/i,
      // Disabled SSL check
      /rejectUnauthorized\s*:\s*false/i,
      /verify\s*=\s*False/i
    ]
  },

  // 5. Path Traversal (CWE-22)
  {
    id: "sast-path-traversal",
    name: "Path Traversal",
    cwe: "CWE-22",
    owasp: "A01:2021 - Broken Access Control",
    severity: "high",
    description: "File path constructed from untrusted user input without path normalization or boundary check.",
    fileExtensions: [".java", ".js", ".ts", ".py", ".go", ".cs"],
    patterns: [
      /new\s+File\s*\(\s*[a-zA-Z0-9_]+\s*,\s*(?:req\.|request\.|userInput|[a-zA-Z0-9_]+Path)/i,
      /new\s+FileInputStream\s*\(\s*[a-zA-Z0-9_]+\s*\+\s*(?:req\.|request\.|userInput)/i,
      /fs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:path\.join\s*\(.*?,?\s*req\.|req\.(?:params|query|body))/i,
      /open\s*\(\s*(?:f["'].*?\{.*?(?:path|file|input).*?\}.*?["']|["'].*?["']\s*\+\s*request\.)/i
    ]
  },

  // 6. Insecure Deserialization (CWE-502)
  {
    id: "sast-insecure-deserialization",
    name: "Insecure Deserialization",
    cwe: "CWE-502",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    severity: "high",
    description: "Untrusted stream deserialized using unsafe deserializer, allowing remote code execution.",
    fileExtensions: [".java", ".js", ".ts", ".py", ".php"],
    patterns: [
      /new\s+ObjectInputStream\s*\(\s*.*?\)\.readObject\s*\(\s*\)/i,
      /new\s+XMLDecoder\s*\(\s*.*?\)\.readObject\s*\(\s*\)/i,
      /pickle\.(?:loads|load)\s*\(/i,
      /yaml\.(?:load|unsafe_load)\s*\(\s*.*?Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader)\s*\)/i,
      /serialize\.unserialize\s*\(/i
    ]
  },

  // 7. Weak Cryptography & Password Hashing (CWE-327 / CWE-916)
  {
    id: "sast-weak-cryptography",
    name: "Weak Cryptography / Deprecated Hash Algorithm",
    cwe: "CWE-327",
    owasp: "A02:2021 - Cryptographic Failures",
    severity: "medium",
    description: "Insecure cryptographic cipher (DES/RC4/ECB mode) or deprecated hash algorithm (MD5/SHA-1) detected.",
    fileExtensions: [".java", ".js", ".ts", ".py", ".go", ".cs"],
    patterns: [
      /Cipher\.getInstance\s*\(\s*["'](?:DES|RC4|Blowfish|AES\/ECB\/PKCS5Padding)["']/i,
      /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|md5|sha-1)["']/i,
      /crypto\.createHash\s*\(\s*["'](?:md5|sha1)["']/i,
      /hashlib\.(?:md5|sha1)\s*\(/i
    ]
  },

  // 8. Server-Side Request Forgery (SSRF) (CWE-918)
  {
    id: "sast-ssrf",
    name: "Server-Side Request Forgery (SSRF)",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    severity: "high",
    description: "Untrusted user-supplied URL fetched without allowlist verification.",
    fileExtensions: [".java", ".js", ".ts", ".py"],
    patterns: [
      /new\s+URL\s*\(\s*(?:req\.|request\.|userInput|[a-zA-Z0-9_]+Url)\s*\)\.openConnection/i,
      /axios\.(?:get|post)\s*\(\s*req\.(?:query|body|params)\.[a-zA-Z0-9_]+/i,
      /fetch\s*\(\s*req\.(?:query|body|params)\.[a-zA-Z0-9_]+/i,
      /requests\.(?:get|post)\s*\(\s*request\.(?:args|form|GET|POST)\[/i
    ]
  }
];

const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  "venv",
  ".venv",
  "__pycache__"
]);

export class SastScanner implements SecurityScanner {
  readonly name = "semgrep" as const;
  private semgrepScanner = new SemgrepScanner();

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: NormalizedFinding[] = [];
    const seenFingerprints = new Set<string>();

    // 1. Run Semgrep if available
    try {
      const semgrepRes = await this.semgrepScanner.scan(repoPath);
      if (semgrepRes.status === "success" && semgrepRes.findings.length > 0) {
        for (const f of semgrepRes.findings) {
          f.category = "SAST";
          const fp = `${f.file}:${f.line}:${f.ruleId}`.toLowerCase();
          if (!seenFingerprints.has(fp)) {
            seenFingerprints.add(fp);
            findings.push(f);
          }
        }
      }
    } catch {
      // Semgrep fallback to native SAST analyzer
    }

    // 2. Run High-Precision Native SAST Engine across all supported languages
    try {
      await this.scanDirectory(repoPath, repoPath, findings, seenFingerprints);
    } catch (err) {
      console.error("[sast-scanner] Native SAST scan error:", err);
    }

    return {
      scanner: "semgrep",
      status: "success",
      findings,
      executionTimeMs: Date.now() - startTime
    };
  }

  private async scanDirectory(
    basePath: string,
    currentPath: string,
    findings: NormalizedFinding[],
    seenFingerprints: Set<string>
  ): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(currentPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name) && !entry.name.startsWith(".")) {
          await this.scanDirectory(basePath, fullPath, findings, seenFingerprints);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        const applicableRules = SAST_RULES.filter((r) => r.fileExtensions.includes(ext));

        if (applicableRules.length === 0) continue;

        try {
          const content = await fs.readFile(fullPath, "utf-8");
          const lines = content.split("\n");
          const relativePath = path.relative(basePath, fullPath).replace(/\\/g, "/");

          for (const rule of applicableRules) {
            for (let i = 0; i < lines.length; i++) {
              const lineContent = lines[i];
              // 4-line sliding window for multi-line syntax
              const windowContent = lines.slice(i, Math.min(i + 5, lines.length)).join("\n");

              for (const pattern of rule.patterns) {
                if (pattern.test(lineContent) || pattern.test(windowContent)) {
                  const fp = `${relativePath}:${i + 1}:${rule.id}`.toLowerCase();
                  if (!seenFingerprints.has(fp)) {
                    seenFingerprints.add(fp);
                    findings.push({
                      tool: "semgrep",
                      category: "SAST",
                      file: relativePath,
                      line: i + 1,
                      ruleId: rule.id,
                      title: rule.name,
                      description: rule.description,
                      codeSnippet: lineContent.trim() || windowContent.slice(0, 500),
                      secretRef: null,
                      severity: rule.severity,
                      cwe: rule.cwe
                    });
                  }
                  break;
                }
              }
            }
          }
        } catch {
          // Ignore unreadable files
        }
      }
    }
  }
}
