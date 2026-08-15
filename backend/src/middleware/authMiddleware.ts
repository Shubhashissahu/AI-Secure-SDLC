import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { AppError } from "./errorHandler";

export interface AuthenticatedRequest extends Request {
    user?: { id: string; role: string };
}

/**
 * Verifies the Authorization: Bearer <token> header on every protected route.
 *
 * FIX #1: Removed the dangerous `!process.env.NODE_ENV` backdoor that would
 * silently grant admin access on any server where NODE_ENV was not set.
 * Auth bypass is now only allowed via an explicit DISABLE_AUTH=true env flag.
 * This prevents the bypass from activating accidentally on staging/production.
 */
export function requireAuth(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
    // Explicit opt-in bypass for local development only — never for production
    if (process.env.DISABLE_AUTH === "true" && process.env.NODE_ENV !== "production") {
        req.user = { id: "dev-user-id", role: "admin" };
        return next();
    }

    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
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