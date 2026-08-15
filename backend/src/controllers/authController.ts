import { Request, Response } from "express";
import jwt, { SignOptions } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { z } from "zod";
import User from "../models/User";
import { AppError } from "../middleware/errorHandler";
import { asyncHandler } from "../utils/asyncHandler";

const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(10, "Password must be at least 10 characters"),
    name: z.string().min(1)
});

function signToken(userId: string, role: string): string {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new AppError("Server misconfiguration: JWT_SECRET not set", 500);
    }
    const options: SignOptions = {
        expiresIn: (process.env.JWT_EXPIRES_IN || "8h") as SignOptions["expiresIn"]
    };
    return jwt.sign({ sub: userId, role }, secret, options);
}

/**
 * POST /api/auth/register
 *
 * Deliberately does NOT accept a `role` field from the request body — every
 * self-registered account is "developer" by default, EXCEPT the very first
 * user ever created, who becomes "admin" automatically. This is a standard
 * bootstrap pattern: without it, the system starts in a deadlock where an
 * admin is required to promote anyone to admin, but no admin exists yet to
 * do the promoting. After the first account, this path never fires again.
 */
export const register = asyncHandler(async (req: Request, res: Response) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
        throw new AppError(`Invalid registration payload: ${parsed.error.message}`, 400);
    }

    const existing = await User.findOne({ email: parsed.data.email });
    if (existing) {
        // Same message as "wrong password" would give on login — avoid
        // confirming which emails are registered via a distinct error message.
        throw new AppError("Registration failed", 409);
    }

    const isFirstUser = (await User.countDocuments()) === 0;

    const passwordHash = await bcrypt.hash(parsed.data.password, 12);
    const user = await User.create({
        email: parsed.data.email,
        passwordHash,
        name: parsed.data.name,
        role: isFirstUser ? "admin" : "developer"
    });

    const token = signToken(String(user._id), user.role);

    res.status(201).json({
        success: true,
        data: { token, user: { id: user._id, email: user.email, name: user.name, role: user.role } }
    });
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1)
});

/**
 * POST /api/auth/login
 *
 * Uses the same "Invalid credentials" message whether the email doesn't
 * exist or the password is wrong — a different message for each would let
 * an attacker enumerate registered emails.
 */
export const login = asyncHandler(async (req: Request, res: Response) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
        throw new AppError("Invalid credentials", 401);
    }

    const user = await User.findOne({ email: parsed.data.email }).select("+passwordHash");
    if (!user) {
        throw new AppError("Invalid credentials", 401);
    }

    const matches = await user.comparePassword(parsed.data.password);
    if (!matches) {
        throw new AppError("Invalid credentials", 401);
    }

    const token = signToken(String(user._id), user.role);

    res.status(200).json({
        success: true,
        data: { token, user: { id: user._id, email: user.email, name: user.name, role: user.role } }
    });
});

const updateRoleSchema = z.object({
    role: z.enum(["admin", "developer", "viewer", "service"])
});

/**
 * PATCH /api/auth/users/:id/role
 * Admin-only (see requireRole("admin") in authRoutes.ts). This is how a
 * "service" role account gets created for the CI workflow (Phase 6) — an
 * admin registers a normal account for it, then promotes it here. There is
 * deliberately no self-service way to become "service" or "admin".
 */
export const updateUserRole = asyncHandler(async (req: Request, res: Response) => {
    const parsed = updateRoleSchema.safeParse(req.body);
    if (!parsed.success) {
        throw new AppError(`Invalid role payload: ${parsed.error.message}`, 400);
    }

    const user = await User.findByIdAndUpdate(
        req.params.id,
        { role: parsed.data.role },
        { new: true }
    );

    if (!user) {
        throw new AppError("User not found", 404);
    }

    res.status(200).json({
        success: true,
        data: { id: user._id, email: user.email, name: user.name, role: user.role }
    });
});