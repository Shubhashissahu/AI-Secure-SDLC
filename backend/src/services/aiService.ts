import axios, { AxiosInstance } from "axios";

export interface AIReviewRequest {
  finding: {
    file: string;
    line: number;
    ruleId: string;
    codeSnippet: string;
    tool: "semgrep" | "gitleaks" | "trivy";
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
  private client!: AxiosInstance;
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
      this.client = axios.create({
        baseURL: "https://api.anthropic.com",
        headers: {
          "x-api-key": this.apiKey,
          "Content-Type": "application/json"
        }
      });
    }
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
        return await this.reviewWithLocalModel(prompt);
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
    const response = await this.client.post("/messages", {
      model: "claude-3-sonnet-20240229",
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

  private async reviewWithLocalModel(_prompt: string): Promise<AIReviewResult> {
    // Placeholder for local model integration (Ollama, LM Studio, etc.)
    // For MVP, return a conservative assessment
    return {
      isRealVulnerability: true,
      confidence: 75,
      attackScenario: "Potential security issue detected by scanner",
      cwe: "CWE-200",
      owasp: "A02:2021",
      exploitability: "medium",
      remediation: {
        patch: "Review and fix according to scanner recommendations",
        explanation: "Scanner flagged a potential issue that requires manual review"
      }
    };
  }

  /**
   * Generate a remediation summary for a set of findings.
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
      if (this.provider === "openai") {
        const response = await this.client.post("/chat/completions", {
          model: this.model,
          messages: [{ role: "user", content: prompt }],
          max_tokens: 500
        });
        return response.data.choices[0].message.content;
      }
    } catch (error) {
      console.error("[ai-service] Report generation failed:", error);
      return "Unable to generate report at this time.";
    }

    return "Report generated.";
  }
}
