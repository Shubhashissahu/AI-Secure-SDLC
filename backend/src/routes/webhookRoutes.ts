import { Router, Request, Response, NextFunction } from "express";
import { handleGitHubWebhook, verifyWebhookSignature } from "../controllers/webhookController";

const router = Router();

/**
 * Middleware to verify GitHub webhook signature.
 * Must be applied BEFORE express.json() to access raw body.
 */
function githubWebhookMiddleware(req: Request, res: Response, next: NextFunction): void {
  const signature = req.headers["x-hub-signature-256"] as string;
  const payload = (req as any).rawBody || "";

  if (!signature) {
    res.status(401).json({ success: false, message: "Missing signature header" });
    return;
  }

  // Get webhook secret from query param or body
  // In production, you'd retrieve this from the database based on the repository
  const secret = process.env.GITHUB_WEBHOOK_SECRET || "";

  if (!verifyWebhookSignature(payload, signature, secret)) {
    res.status(401).json({ success: false, message: "Invalid webhook signature" });
    return;
  }

  // Parse the JSON body for the handler
  try {
    (req as any).body = JSON.parse(payload);
    next();
  } catch (error) {
    res.status(400).json({ success: false, message: "Invalid JSON payload" });
  }
}

/**
 * POST /api/webhook/github
 * GitHub webhook endpoint for PR events.
 */
router.post("/github", githubWebhookMiddleware, handleGitHubWebhook);

export default router;
