import { Request, Response, NextFunction } from "express";

/**
 * Wrapper for async route handlers. Catches promise rejections and passes them
 * to the error handler middleware instead of causing unhandled rejections.
 */
export function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
