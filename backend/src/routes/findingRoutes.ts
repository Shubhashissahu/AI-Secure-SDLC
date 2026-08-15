import { Router } from "express";
import {
  listFindings,
  getFinding,
  updateFindingStatus,
  getOllamaStatusHandler,
  triggerAiReview
} from "../controllers/findingController";
import { scanExecutionLimiter } from "../middleware/rateLimiter";

const router = Router();

router.get("/", listFindings);
router.get("/ollama-status", getOllamaStatusHandler);
router.get("/:id", getFinding);
router.patch("/:id", updateFindingStatus);
router.post("/:id/ai-review", scanExecutionLimiter, triggerAiReview);

export default router;