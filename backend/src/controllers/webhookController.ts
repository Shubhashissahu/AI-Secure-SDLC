import crypto from "crypto";
import { Request, Response } from "express";
import { z } from "zod";
import Scan from "../models/Scan";
import Repository from "../models/Repository";
import { AppError } from "../middleware/errorHandler";
import { asyncHandler } from "../utils/asyncHandler";
import { enqueueScanJob } from "../queue/scanQueue";

/**
 * GitHub webhook payload schema (PR event).
 */
const webhookPayloadSchema = z.object({
  action: z.enum(["opened", "synchronize"]),
  pull_request: z.object({
    number: z.number(),
    title: z.string(),
    body: z.string().optional(),
    head: z.object({
      sha: z.string(),
      ref: z.string(),
      repo: z.object({
        name: z.string(),
        full_name: z.string(),
        owner: z.object({
          login: z.string()
        })
      })
    })
  })
});

/**
 * Verify GitHub webhook HMAC signature.
 * This ensures the webhook came from GitHub and not an attacker.
 */
export function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): boolean {
  try {
    const hash = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("hex");
    const expectedSignature = `sha256=${hash}`;
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    return false;
  }
}

/**
 * POST /api/webhook/github
 * Webhook endpoint for GitHub PR events.
 * - Verifies HMAC signature
 * - Creates a scan record
 * - Enqueues background job into Redis / BullMQ queue (checkout -> scanners -> Ollama AI review -> risk engine -> CI gate)
 */
export const handleGitHubWebhook = asyncHandler(async (req: Request, res: Response) => {
  const signature = req.headers["x-hub-signature-256"] as string;
  if (!signature) {
    throw new AppError("Missing X-Hub-Signature-256 header", 401);
  }

  const parsed = webhookPayloadSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(`Invalid webhook payload: ${parsed.error.message}`, 400);
  }

  const event = parsed.data;
  const { owner, name } = {
    owner: event.pull_request.head.repo.owner.login,
    name: event.pull_request.head.repo.name
  };

  // Look up repository to verify secret
  const repository = await Repository.findOne({ owner, name }).select("+webhookSecret");

  if (!repository) {
    throw new AppError(
      `Repository ${owner}/${name} not registered. Register via POST /api/repositories first.`,
      404
    );
  }

  // Verify HMAC signature if webhookSecret is configured
  if (repository.webhookSecret && !verifyWebhookSignature((req as any).rawBody || JSON.stringify(req.body), signature, repository.webhookSecret)) {
    throw new AppError("Invalid webhook HMAC signature", 401);
  }

  // Create scan record in pending state
  const scan = await Scan.create({
    repositoryId: repository._id,
    prNumber: event.pull_request.number,
    commitSha: event.pull_request.head.sha,
    status: "pending",
    triggeredBy: event.pull_request.head.repo.owner.login,
    startedAt: new Date(),
    gateResult: "pending"
  });

  // Enqueue background scan job
  const { jobStatus, jobId } = await enqueueScanJob(String(scan._id));

  // Acknowledge webhook immediately (202 Accepted)
  res.status(202).json({
    success: true,
    message: "Scan initiated and job enqueued",
    scanId: scan._id,
    jobId,
    jobStatus
  });
});
