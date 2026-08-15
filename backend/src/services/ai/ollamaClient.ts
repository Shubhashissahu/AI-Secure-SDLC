import axios from "axios";

const OLLAMA_TIMEOUT_MS = 60 * 1000;

interface OllamaGenerateResponse {
  response: string;
  done: boolean;
}

interface OllamaTagModel {
  name: string;
  model: string;
  size: number;
}

interface OllamaTagsResponse {
  models: OllamaTagModel[];
}

export interface OllamaStatus {
  isConnected: boolean;
  baseUrl: string;
  configuredModel: string;
  activeModel: string;
  availableModels: string[];
  message?: string;
}

export async function checkOllamaStatus(): Promise<OllamaStatus> {
  const baseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
  const configuredModel = process.env.OLLAMA_MODEL || "codellama:13b";

  try {
    const res = await axios.get<OllamaTagsResponse>(`${baseUrl}/api/tags`, {
      timeout: 3000
    });
    const models = (res.data.models || []).map((m) => m.name);
    let activeModel = configuredModel;

    if (models.length > 0 && !models.includes(configuredModel)) {
      // Pick exact match or first available model
      const match = models.find((m) => m.toLowerCase().includes("llama") || m.toLowerCase().includes("coder"));
      activeModel = match || models[0];
    }

    return {
      isConnected: true,
      baseUrl,
      configuredModel,
      activeModel,
      availableModels: models,
      message: `Connected to Ollama at ${baseUrl}`
    };
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : "Unreachable";
    return {
      isConnected: false,
      baseUrl,
      configuredModel,
      activeModel: configuredModel,
      availableModels: [],
      message: `Ollama offline (${errMsg})`
    };
  }
}

/**
 * Calls Ollama's /api/generate endpoint with a single prompt.
 */
export async function callOllama(prompt: string): Promise<string> {
  const status = await checkOllamaStatus();
  if (!status.isConnected) {
    throw new Error(`Ollama service offline at ${status.baseUrl}`);
  }

  const response = await axios.post<OllamaGenerateResponse>(
    `${status.baseUrl}/api/generate`,
    {
      model: status.activeModel,
      prompt,
      stream: false,
      options: { temperature: 0.1 }
    },
    { timeout: OLLAMA_TIMEOUT_MS }
  );

  return response.data.response;
}

/**
 * Extracts JSON object from raw LLM output text.
 */
export function extractJsonObject(rawText: string): Record<string, unknown> | null {
  const fenceStripped = rawText.replace(/```json/gi, "").replace(/```/g, "").trim();

  const firstBrace = fenceStripped.indexOf("{");
  const lastBrace = fenceStripped.lastIndexOf("}");

  if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
    return null;
  }

  const candidate = fenceStripped.slice(firstBrace, lastBrace + 1);

  try {
    return JSON.parse(candidate);
  } catch {
    return null;
  }
}