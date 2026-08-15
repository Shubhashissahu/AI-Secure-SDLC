import rateLimit, { RateLimitRequestHandler } from "express-rate-limit";
import { Request, Response } from "express";

/**
 * Standard 429 response handler providing consistent, actionable feedback.
 */
function createRateLimitHandler(message: string) {
  return (_req: Request, res: Response): void => {
    const retryAfter = res.getHeader("Retry-After") || 60;
    res.status(429).json({
      success: false,
      message,
      retryAfter: Number(retryAfter) || 60
    });
  };
}

const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;

/**
 * General API Limiter:
 * Applied to standard read/browse traffic across the application.
 * In development, allows comfortable headroom (default 2000 requests / 15 min)
 * so multiple dashboard components and fast navigation never hit 429.
 */
export const apiLimiter: RateLimitRequestHandler = rateLimit({
  windowMs,
  max: Number(process.env.RATE_LIMIT_MAX) || (process.env.NODE_ENV === "production" ? 500 : 2000),
  standardHeaders: true,
  legacyHeaders: false,
  handler: createRateLimitHandler("Too many requests from this IP. Please try again later.")
});

/**
 * Auth Limiter:
 * Protects login / token endpoints against brute-force attacks.
 */
export const authLimiter: RateLimitRequestHandler = rateLimit({
  windowMs,
  max: Number(process.env.RATE_LIMIT_AUTH_MAX) || 50,
  standardHeaders: true,
  legacyHeaders: false,
  handler: createRateLimitHandler("Too many authentication attempts. Please try again later.")
});

/**
 * Scan Execution Limiter:
 * Protects CPU-heavy / AI-heavy scanning trigger endpoints against spam & abuse.
 */
export const scanExecutionLimiter: RateLimitRequestHandler = rateLimit({
  windowMs,
  max: Number(process.env.RATE_LIMIT_SCAN_MAX) || 60,
  standardHeaders: true,
  legacyHeaders: false,
  handler: createRateLimitHandler("Too many scan execution requests. Please wait a moment before starting new scans.")
});
