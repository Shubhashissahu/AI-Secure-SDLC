import axios, { AxiosInstance } from "axios";

// FIX #10: Expanded tool type to include all 10+ scanner tools, not just 3
export type AIReviewTool =
  | "semgrep"
  | "gitleaks"
  | "trivy"
  | "osv"
  | "secret-scanner"
  | "sast-scanner"
  | "ai-security-scanner"
  | "container-scanner"
  | "iac-scanner"
  | "trivy-config"
  | "cicd-scanner"
  | "codeql"
  | "dependency-check";

export interface AIReviewRequest {
  finding: {
    file: string;
    line: number;
    ruleId: string;
    codeSnippet: string;
    tool: AIReviewTool;  // FIX #10: was incorrectly limited to 3 tools
    severity: "critical" | "high" | "medium" | "low";
  };
  context?: {
    prTitle?: string;
    prDescription?: string;
    changedFiles?: string[];
  };
}

export interface AIReviewResult {
  isRealVulnerability: boolean;
  confidence: number; // 0-100
  attackScenario: string;
  cwe: string;
  owasp: string;
  exploitability: "low" | "medium" | "high";
  remediation: {
    patch: string;
    explanation: string;
  };
}

/**
 * AI-powered security code review service.
 * Uses LLM (OpenAI, Anthropic, etc.) to validate scanner findings,
 * assess exploitability, and suggest remediation.
 */
export class AIService {
  private apiKey: string;
  private model: string;
  private client: AxiosInstance | null = null;  // FIX #17: was declared with ! (never null safety)
  private provider: "openai" | "anthropic" | "local";

  constructor(
    apiKey?: string,
    model: string = "gpt-4-turbo",
    provider: "openai" | "anthropic" | "local" = "openai"
  ) {
    this.apiKey = apiKey || process.env.AI_API_KEY || "";
    this.model = model;
    this.provider = provider;

    if (provider === "openai") {
      this.client = axios.create({
        baseURL: "https://api.openai.com/v1",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json"
        }
      });
    } else if (provider === "anthropic") {
      // FIX #15: Added required anthropic-version header (API rejects requests without it)
      this.client = axios.create({
        baseURL: "https://api.anthropic.com",
        headers: {
          "x-api-key": this.apiKey,
          "anthropic-version": "2023-06-01",
          "Content-Type": "application/json"
        }
      });
    }
    // FIX #17: local provider intentionally leaves this.client = null;
    // reviewWithLocalModel does not use this.client so it is safe.
  }

  /**
   * Review a security finding using LLM to assess:
   * - Is it a real vulnerability?
   * - What's the attack scenario?
   * - How exploitable is it?
   * - What's the remediation?
   */
  async reviewFinding(req: AIReviewRequest): Promise<AIReviewResult> {
    const prompt = this.buildReviewPrompt(req);

    try {
      if (this.provider === "openai") {
        return await this.reviewWithOpenAI(prompt);
      } else if (this.provider === "anthropic") {
        return await this.reviewWithAnthropic(prompt);
      } else {
        return await this.reviewWithLocalModel(prompt, req);
      }
    } catch (error) {
      console.error("[ai-service] Review failed:", error);
      throw new Error(`AI review failed: ${error}`);
    }
  }

  private buildReviewPrompt(req: AIReviewRequest): string {
    const { finding, context } = req;
    return `
You are an expert security code reviewer. Analyze the following security finding and provide a detailed assessment.

## Detected Finding
- Tool: ${finding.tool}
- Rule: ${finding.ruleId}
- File: ${finding.file}:${finding.line}
- Severity: ${finding.severity}
- Code Snippet:
\`\`\`
${finding.codeSnippet}
\`\`\`

${context?.prTitle ? `## PR Title: ${context.prTitle}` : ""}
${context?.prDescription ? `## PR Description: ${context.prDescription}` : ""}

## Your Assessment (respond in JSON format):
{
  "isRealVulnerability": boolean,
  "confidence": 0-100,
  "attackScenario": "detailed explanation of how this could be exploited",
  "cwe": "CWE-XXX identifying the weakness",
  "owasp": "A01:2021 or relevant OWASP category",
  "exploitability": "low|medium|high",
  "remediation": {
    "patch": "code fix",
    "explanation": "why this fixes the issue"
  }
}

Be concise but thorough. Focus on practical exploitability and real risk.
`;
  }

  private async reviewWithOpenAI(prompt: string): Promise<AIReviewResult> {
    if (!this.client) throw new Error("[ai-service] OpenAI client not initialized");
    const response = await this.client.post("/chat/completions", {
      model: this.model,
      messages: [
        {
          role: "system",
          content: "You are an expert security code reviewer. Respond in valid JSON format only."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      temperature: 0.3, // Lower temperature for consistency
      max_tokens: 1000,
      response_format: { type: "json_object" }
    });

    const content = response.data.choices[0].message.content;
    const parsed = JSON.parse(content);

    return {
      isRealVulnerability: parsed.isRealVulnerability,
      confidence: parsed.confidence,
      attackScenario: parsed.attackScenario,
      cwe: parsed.cwe,
      owasp: parsed.owasp,
      exploitability: parsed.exploitability,
      remediation: parsed.remediation
    };
  }

  private async reviewWithAnthropic(prompt: string): Promise<AIReviewResult> {
    if (!this.client) throw new Error("[ai-service] Anthropic client not initialized");
    const response = await this.client.post("/v1/messages", {
      model: "claude-3-5-sonnet-20241022",
      max_tokens: 1024,
      messages: [
        {
          role: "user",
          content: prompt
        }
      ]
    });

    const content = response.data.content[0].text;
    const parsed = JSON.parse(content);

    return {
      isRealVulnerability: parsed.isRealVulnerability,
      confidence: parsed.confidence,
      attackScenario: parsed.attackScenario,
      cwe: parsed.cwe,
      owasp: parsed.owasp,
      exploitability: parsed.exploitability,
      remediation: parsed.remediation
    };
  }

  /**
   * FIX #17 & #23: Local model (Ollama) now actually makes a real API call
   * to the configured Ollama endpoint instead of returning a hardcoded stub.
   * Falls back to a conservative assessment only if Ollama is unreachable.
   */
  private async reviewWithLocalModel(prompt: string, req: AIReviewRequest): Promise<AIReviewResult> {
    const ollamaBase = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
    const ollamaModel = process.env.OLLAMA_MODEL || "codellama:13b";

    try {
      const ollamaClient = axios.create({ baseURL: ollamaBase, timeout: 120000 });
      const response = await ollamaClient.post("/api/generate", {
        model: ollamaModel,
        prompt: `${prompt}\n\nRespond ONLY with valid JSON matching the schema above.`,
        stream: false,
        format: "json"
      });

      const text: string = response.data?.response || "";
      const parsed = JSON.parse(text);

      return {
        isRealVulnerability: Boolean(parsed.isRealVulnerability),
        confidence: Number(parsed.confidence) || 60,
        attackScenario: parsed.attackScenario || "Potential security issue detected by scanner",
        cwe: parsed.cwe || "CWE-200",
        owasp: parsed.owasp || "A05:2021",
        exploitability: parsed.exploitability || "medium",
        remediation: parsed.remediation || {
          patch: "",
          explanation: "Review according to scanner recommendations"
        }
      };
    } catch (err) {
      // Ollama unavailable — log and return conservative fallback
      console.warn(`[ai-service] Ollama at ${ollamaBase} is unreachable: ${err}. Using conservative fallback.`);
      return {
        isRealVulnerability: true,
        confidence: 50,
        attackScenario: `Potential ${req.finding.ruleId} issue in ${req.finding.file}:${req.finding.line} — manual review required (AI service offline)`,
        cwe: "CWE-200",
        owasp: "A05:2021",
        exploitability: "medium",
        remediation: {
          patch: "Review and fix according to scanner recommendations",
          explanation: "AI review unavailable — scanner flagged a potential issue requiring manual review"
        }
      };
    }
  }

  /**
   * Generate a remediation summary for a set of findings.
   * FIX #9: All providers (OpenAI, Anthropic, local) now generate a real report.
   * Previously Anthropic and local silently returned "Report generated." stub.
   */
  async generateRemediationReport(findings: AIReviewRequest[]): Promise<string> {
    const summary = findings
      .map(
        (f) =>
          `- ${f.finding.file}:${f.finding.line} (${f.finding.tool}): ${f.finding.ruleId}`
      )
      .join("\n");

    const prompt = `
You are a security expert preparing a remediation report.
Here are the security findings that need to be addressed:

${summary}

Provide a brief action plan (2-3 sentences) prioritized by severity.
`;

    try {
      if (this.provider === "openai" && this.client) {
        const response = await this.client.post("/chat/completions", {
          model: this.model,
          messages: [{ role: "user", content: prompt }],
          max_tokens: 500
        });
        return response.data.choices[0].message.content;
      }

      // FIX #9: Anthropic branch now also generates a real report
      if (this.provider === "anthropic" && this.client) {
        const response = await this.client.post("/v1/messages", {
          model: "claude-3-5-sonnet-20241022",
          max_tokens: 500,
          messages: [{ role: "user", content: prompt }]
        });
        return response.data.content[0].text;
      }

      // FIX #9: Local Ollama branch generates a real report
      if (this.provider === "local") {
        const ollamaBase = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
        const ollamaModel = process.env.OLLAMA_MODEL || "codellama:13b";
        const ollamaClient = axios.create({ baseURL: ollamaBase, timeout: 60000 });
        const response = await ollamaClient.post("/api/generate", {
          model: ollamaModel,
          prompt,
          stream: false
        });
        return response.data?.response || "Unable to generate report (Ollama returned empty response).";
      }
    } catch (error) {
      console.error("[ai-service] Report generation failed:", error);
      return "Unable to generate report at this time.";
    }

    return "Unable to generate report: no AI provider configured.";
  }
}
