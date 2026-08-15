import { Router } from "express";
import { getDashboardStats } from "../controllers/dashboardController";

const router = Router();

router.get("/", getDashboardStats);
router.get("/stats", getDashboardStats);

export default router;
