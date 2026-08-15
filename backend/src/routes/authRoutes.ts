import { Router } from "express";
import { register, login, updateUserRole } from "../controllers/authController";
import { requireAuth, requireRole } from "../middleware/authMiddleware";
import { authLimiter } from "../middleware/rateLimiter";

const router = Router();

router.post("/register", authLimiter, register);
router.post("/login", authLimiter, login);
router.patch("/users/:id/role", requireAuth, requireRole("admin"), updateUserRole);

export default router;