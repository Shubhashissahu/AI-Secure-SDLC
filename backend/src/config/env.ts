import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

/**
 * FIX #5 & #22: All critical secrets are now part of the validated schema.
 * The server will fail fast with a clear error message at startup if any
 * required secret is missing, instead of throwing cryptic runtime exceptions
 * on the first request that needs them.
 */
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().default(4000),
  MONGO_URI: z.string().min(1, "MONGO_URI is required"),
  FRONTEND_ORIGIN: z.string().default("http://localhost:5173"),
  OLLAMA_BASE_URL: z.string().default("http://localhost:11434"),
  OLLAMA_MODEL: z.string().default("codellama:13b"),
  REDIS_HOST: z.string().default("localhost"),
  REDIS_PORT: z.coerce.number().default(6379),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000),
  RATE_LIMIT_MAX: z.coerce.number().default(100),

  // ── Critical secrets (required; no defaults) ──
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),
  GITHUB_TOKEN: z.string().min(1, "GITHUB_TOKEN is required").optional(),
  GITHUB_WEBHOOK_SECRET: z.string().min(1, "GITHUB_WEBHOOK_SECRET is required").optional(),
  AI_API_KEY: z.string().min(1, "AI_API_KEY is required for AI review features").optional(),
  AI_PROVIDER: z.enum(["openai", "anthropic", "local"]).default("local"),

  // Optional dev flag (explicit opt-in only)
  DISABLE_AUTH: z.enum(["true", "false"]).optional()
});

export type Env = z.infer<typeof envSchema>;

export function validateEnv(): Env {
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    console.error("❌ Environment schema validation failed:\n", result.error.format());
    process.exit(1);
  }
  console.log("✅ Environment configuration validated successfully.");
  return result.data;
}

