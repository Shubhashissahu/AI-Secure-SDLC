import { Request, Response, NextFunction } from "express";

export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Last-resort error handler. Never leaks stack traces or internal error
 * details to the client in production — this is a security tool, so its own
 * error surface should not become an information-disclosure vector.
 */
export function errorHandler(
  err: Error | AppError,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
): void {
  const statusCode = err instanceof AppError ? err.statusCode : 500;
  const isProd = process.env.NODE_ENV === "production";

  // eslint-disable-next-line no-console
  console.error(`[error] ${err.message}`, isProd ? "" : err.stack);

  res.status(statusCode).json({
    success: false,
    message: statusCode === 500 && isProd ? "Internal server error" : err.message
  });
}
