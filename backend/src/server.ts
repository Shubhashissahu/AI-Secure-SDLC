import express, { Request, Response } from "express";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";

import { connectDB } from "./config/db";
import { validateEnv } from "./config/env";
import { errorHandler } from "./middleware/errorHandler";
import { requireAuth } from "./middleware/authMiddleware";
import { apiLimiter, authLimiter, scanExecutionLimiter } from "./middleware/rateLimiter";
import authRoutes from "./routes/authRoutes";
import scanRoutes from "./routes/scanRoutes";
import findingRoutes from "./routes/findingRoutes";
import repositoryRoutes from "./routes/repositoryRoutes";
import dashboardRoutes from "./routes/dashboardRoutes";
import webhookRoutes from "./routes/webhookRoutes";

dotenv.config();

// FIX #14: Validate env schema at startup — fails fast if required vars are missing
validateEnv();

const app = express();
const PORT = process.env.PORT || 4000;

// Trust reverse proxy headers if behind nginx/caddy/load balancers
if (process.env.TRUST_PROXY === "true" || process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// ---- Security middleware (applied before anything else) ----
app.use(helmet());
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || "http://localhost:5173",
    credentials: true
  })
);

// Apply general API rate limiter
app.use(apiLimiter);

app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// Raw-body capture for webhook HMAC signature verification.
// This MUST be mounted before express.json() so the webhook route can
// access the raw Buffer for signature computation.
app.use("/api/webhook", express.raw({ type: "application/json", limit: "2mb" }), (req, _res, next) => {
  (req as any).rawBody = req.body.toString("utf-8");
  try { req.body = JSON.parse((req as any).rawBody); } catch { /* handled in route */ }
  next();
});

// JSON parsing for all other routes.
app.use(express.json({ limit: "2mb" }));

// ---- Health checks & Root ----
app.get("/", (_req: Request, res: Response) => {
  res.status(200).json({ status: "ok", message: "SecureFlow API is running" });
});

app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({ status: "ok", service: "secureflow-backend" });
});

// ---- API routes ----
// FIX #4: authLimiter applied to /api/auth to prevent brute-force attacks.
// scanExecutionLimiter applied to /api/scans to prevent scan spam/abuse.
app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/scans", requireAuth, scanExecutionLimiter, scanRoutes);
app.use("/api/findings", requireAuth, findingRoutes);
app.use("/api/repositories", requireAuth, repositoryRoutes);
app.use("/api/dashboard", requireAuth, dashboardRoutes);
app.use("/api/webhook", webhookRoutes); // HMAC-authenticated, not JWT

// ---- 404 handler ----
app.use((_req: Request, res: Response) => {
  res.status(404).json({ success: false, message: "Route not found" });
});

// ---- Centralized error handler (must be last) ----
app.use(errorHandler);

async function start(): Promise<void> {
  await connectDB();
  const server = app.listen(PORT as number, "0.0.0.0", () => {
    // eslint-disable-next-line no-console
    console.log(`[server] secureflow backend listening on port ${PORT}`);
  });

  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      // eslint-disable-next-line no-console
      console.error(
        `[server] ❌ Port ${PORT} is already in use.\n` +
        `[server] Run this to free it: netstat -ano | findstr :${PORT}\n` +
        `[server] Then: taskkill /PID <pid> /F`
      );
    } else {
      // eslint-disable-next-line no-console
      console.error("[server] Unexpected server error:", err);
    }
    process.exit(1);
  });
}

start().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("[server] Failed to start:", err);
  process.exit(1);
});

export default app;