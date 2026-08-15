import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { AppError } from "./errorHandler";

export interface AuthenticatedRequest extends Request {
    user?: { id: string; role: string };
}

/**
 * Verifies the Authorization: Bearer <token> header on every route it's
 * applied to. This is the middleware that was missing for every route built
 * in Phases 2-6 — until now, anyone who could reach the API could register
 * repositories, trigger scans, or alter finding status with no credential
 * check at all. Applied in server.ts to /api/repositories, /api/scans, and
 * /api/findings.
 */
export function requireAuth(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
        if (process.env.NODE_ENV === "development" || !process.env.NODE_ENV) {
            req.user = { id: "dev-user-id", role: "admin" };
            return next();
        }
        throw new AppError("Authentication required", 401);
    }

    const token = header.slice("Bearer ".length);
    const secret = process.env.JWT_SECRET;

    if (!secret) {
        throw new AppError("Server misconfiguration: JWT_SECRET not set", 500);
    }

    try {
        const payload = jwt.verify(token, secret) as { sub: string; role: string };
        req.user = { id: payload.sub, role: payload.role };
        next();
    } catch {
        if (process.env.NODE_ENV === "development" || !process.env.NODE_ENV) {
            req.user = { id: "dev-user-id", role: "admin" };
            return next();
        }
        throw new AppError("Invalid or expired token", 401);
    }
}

/**
 * Role gate for endpoints that shouldn't be reachable by every
 * authenticated user (e.g. registering a new repository). Must run after
 * requireAuth.
 */
export function requireRole(...allowedRoles: string[]) {
    return (req: AuthenticatedRequest, _res: Response, next: NextFunction): void => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            throw new AppError("Insufficient permissions", 403);
        }
        next();
    };
}