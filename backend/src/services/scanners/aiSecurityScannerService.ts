import path from "path";
import { promises as fs } from "fs";
import { SecurityScanner, ScannerResult } from "./SecurityScanner";
import { NormalizedFinding } from "./types";

interface AiSecurityRule {
  id: string;
  name: string;
  cwe: string;
  owasp: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  patterns: RegExp[];
  negativePatterns?: RegExp[];
  fileExtensions: string[];
}

const AI_SECURITY_RULES: AiSecurityRule[] = [
  // 1. Prompt Injection (OWASP-LLM01 / CWE-20)
  {
    id: "prompt-injection",
    name: "Prompt Injection",
    cwe: "CWE-20",
    owasp: "OWASP-LLM01: Prompt Injection",
    severity: "high",
    description: "User input directly formatted into an LLM prompt or adversarial prompt override instructions detected (Ignore previous instructions, Forget rules, Reveal system prompt).",
    fileExtensions: [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"],
    patterns: [
      // Direct adversarial injection keywords
      /ignore\s+(?:all\s+)?previous\s+instructions/i,
      /forget\s+(?:all\s+)?(?:your\s+)?rules/i,
      /reveal\s+(?:the\s+)?(?:system\s+)?prompt/i,
      /system\s+prompt\s+leakage/i,
      /disregard\s+(?:all\s+)?(?:previous\s+)?instructions/i,
      /bypass\s+safety\s+guidelines/i,
      // Python prompt templates / concatenation
      /(?:prompt|messages|user_prompt|system_prompt)\s*=\s*f["'].*?\{(?:user_input|input_text|query|userInput|user_query|prompt|msg|text|instruction)\}.*?["']/i,
      /(?:prompt|messages|user_prompt)\s*=\s*["'].*?["']\s*\+\s*(?:user_input|input_text|query|userInput|req\.body|req\.query)/i,
      /(?:ChatCompletion|generate_content|generateContent|completions\.create|chat\.completions\.create)\s*\(\s*.*?messages\s*=\s*\[.*?(?:user_input|query|userInput|req\.body).*?\]/is,
      /PromptTemplate(?:\.from_template|\()[\s\S]*?(?:user_input|input_text|user_query)/i,
      // Node.js template strings
      /(?:prompt|messages|userPrompt)\s*=\s*`.*?(?:\$\{(?:userInput|req\.body|req\.query|prompt|query|input)\}).*?`/i
    ]
  },

  // 2. Sensitive Data Leakage in AI Context (OWASP-LLM06 / CWE-200)
  {
    id: "data-leakage",
    name: "Sensitive Data Leakage",
    cwe: "CWE-200",
    owasp: "OWASP-LLM06: Sensitive Information Disclosure",
    severity: "critical",
    description: "Sensitive information (passwords, API keys, credit cards, emails, PII, system prompts) is exposed in AI prompt context, completion responses, or unmasked logs.",
    fileExtensions: [".py", ".js", ".ts", ".jsx", ".tsx", ".java"],
    patterns: [
      // Password / Credentials in AI context
      /(?:prompt|messages|user_prompt|system_prompt|context)\s*=[\s\S]*?(?:password|passwd|pwd|db_password|api_key|apikey|secret_key|private_key|auth_token)\b/i,
      /f["'].*?\{(?:password|passwd|api_key|apikey|secret_key|token|auth_secret|credit_card|card_number|email|ssn|pii)\}.*?["']/i,
      /`.*?\{(?:password|apiKey|secretToken|creditCard|email|ssn|pii)\}.*?`/i,
      // Credit card regex in AI context/prompt
      /(?:credit_card|card_number|cc_num)\s*=\s*["'][0-9\s-]{13,19}["']/i,
      // Email / PII / API keys in AI context or prompts
      /(?:user_email|customer_email|email_address|emails|pii_data|pii)\s*=\s*["'].*?@.*?["']/i,
      /(?:api_key|openai_key|auth_token)\s*=\s*["'][a-zA-Z0-9_\-]{20,}["']/i,
      // System prompt leakage in responses / logs
      /(?:res\.json|res\.send|return\s+jsonify|return\s+\{)[\s\S]*?(?:system_prompt|systemPrompt|SYSTEM_INSTRUCTION|developer_prompt)/i,
      /(?:console\.log|logger\.(?:info|debug|warn)|print)\s*\(\s*["'].*?(?:system\s+prompt|leakage|sensitive).*?["']\s*,\s*(?:system_prompt|systemPrompt|SYSTEM_PROMPT|sensitive_data|pii)/i,
      /return\s*\{[^}]*?(?:system_prompt|system_instruction|hidden_instructions|sensitive_data)\s*:/i
    ]
  },

  // 3. Insecure Output Handling
  {
    id: "ai-insecure-output-handling",
    name: "Insecure LLM Output Handling (Exec / XSS)",
    cwe: "CWE-79",
    owasp: "OWASP-LLM02: Insecure Output Handling",
    severity: "high",
    description: "Raw LLM output is passed directly to execution sinks (eval, exec, innerHTML, shell commands) without validation.",
    fileExtensions: [".py", ".js", ".ts", ".jsx", ".tsx"],
    patterns: [
      /(?:eval|exec)\s*\(\s*(?:response\.choices|completion\.choices|llm_output|ai_response|completion|result\.response)/i,
      /innerHTML\s*=\s*(?:response\.choices|completion\.choices|llmOutput|aiResponse|completion\.data)/i,
      /(?:dangerouslySetInnerHTML)\s*=\s*\{\s*\{\s*__html:\s*(?:response|completion|aiResult|llmOutput)/i
    ]
  },

  // 4. Excessive Agency
  {
    id: "ai-excessive-agency-autonomous-execution",
    name: "Excessive Agency - Unrestricted Tool Execution",
    cwe: "CWE-863",
    owasp: "OWASP-LLM08: Excessive Agency",
    severity: "high",
    description: "LLM agent or function call output is directly wired to execute system shell commands or destructive database queries without user approval.",
    fileExtensions: [".py", ".js", ".ts"],
    patterns: [
      /(?:os\.system|subprocess\.(?:Popen|run)|child_process\.exec)\s*\(\s*(?:tool_call\.arguments|function_call\.arguments|llm_tool_output|action_input)/i,
      /(?:db\.execute|cursor\.execute)\s*\(\s*(?:tool_call\.arguments|function_args\["query"\])/i
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

export class AiSecurityScanner implements SecurityScanner {
  readonly name = "ai-security-scanner" as const;

  async scan(repoPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: NormalizedFinding[] = [];

    try {
      await this.scanDirectory(repoPath, repoPath, findings);

      return {
        scanner: "ai-security-scanner",
        status: "success",
        findings,
        executionTimeMs: Date.now() - startTime
      };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      console.error("[ai-security-scanner] Scan failed:", errorMsg);
      return {
        scanner: "ai-security-scanner",
        status: "failed",
        findings: [],
        error: errorMsg,
        executionTimeMs: Date.now() - startTime
      };
    }
  }

  private async scanDirectory(basePath: string, currentPath: string, findings: NormalizedFinding[]): Promise<void> {
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
          await this.scanDirectory(basePath, fullPath, findings);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        const applicableRules = AI_SECURITY_RULES.filter((r) => r.fileExtensions.includes(ext));

        if (applicableRules.length === 0) continue;

        try {
          const content = await fs.readFile(fullPath, "utf-8");
          const lines = content.split("\n");
          const relativePath = path.relative(basePath, fullPath).replace(/\\/g, "/");

          for (const rule of applicableRules) {
            for (let i = 0; i < lines.length; i++) {
              const lineContent = lines[i];
              // Also check 3-line sliding window for multi-line expressions
              const windowContent = lines.slice(i, Math.min(i + 4, lines.length)).join("\n");

              for (const pattern of rule.patterns) {
                if (pattern.test(lineContent) || pattern.test(windowContent)) {
                  findings.push({
                    tool: "ai-security-scanner",
                    category: "AI_SECURITY",
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
                  break; // Found matching rule for this line
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
