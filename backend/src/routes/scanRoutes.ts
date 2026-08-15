import { Router } from "express";
import { createScan, triggerCustomRemoteScan, getScan, getScanStatus, getScanSarif, listScans, runScan } from "../controllers/scanController";
import { scanExecutionLimiter } from "../middleware/rateLimiter";

const router = Router();

router.post("/", scanExecutionLimiter, createScan);
router.post("/custom-remote", scanExecutionLimiter, triggerCustomRemoteScan);
router.get("/", listScans);
router.get("/:id", getScan);
router.get("/:id/status", getScanStatus);
router.get("/:id/sarif", getScanSarif);
router.post("/:id/run", scanExecutionLimiter, runScan);

export default router;