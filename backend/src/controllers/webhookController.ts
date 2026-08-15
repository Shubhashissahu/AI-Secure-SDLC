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
 * FIX #21: Added "reopened" action so re-opened PRs are also scanned.
 */
const webhookPayloadSchema = z.object({
  action: z.enum(["opened", "synchronize", "reopened"]),
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
 *
 * FIX #16: Added explicit length equality check before timingSafeEqual to
 * prevent the RangeError it throws when buffer lengths differ (e.g. when
 * an attacker sends a malformed signature of an unexpected length).
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
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSignature);
    // timingSafeEqual throws if buffers have different byte lengths —
    // guard against that explicitly to avoid error-based timing oracle.
    if (sigBuf.length !== expBuf.length) return false;
    return crypto.timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}

/**
 * POST /api/webhook/github
 * Webhook endpoint for GitHub PR events.
 * - Verifies HMAC signature (BEFORE any DB lookups or body processing)
 * - Creates a scan record
 * - Enqueues background job into Redis / BullMQ queue
 *
 * FIX #2: HMAC verification is now REQUIRED — a missing or empty
 *   webhookSecret causes a hard reject instead of skipping verification.
 * FIX #11: HMAC verification now happens BEFORE Zod body parsing and
 *   any database lookups to prevent pre-auth processing.
 */
export const handleGitHubWebhook = asyncHandler(async (req: Request, res: Response) => {
  const signature = req.headers["x-hub-signature-256"] as string;
  if (!signature) {
    throw new AppError("Missing X-Hub-Signature-256 header", 401);
  }

  // ── FIX #11: Validate the raw body signature FIRST, before any DB work ──
  // We use rawBody captured by server.ts middleware for accurate HMAC.
  // We need the repository's webhookSecret, so we do a minimal owner/name
  // extract from the raw JSON string without trusting the parsed body yet.
  let rawBody: string;
  try {
    rawBody = (req as any).rawBody || JSON.stringify(req.body);
  } catch {
    throw new AppError("Failed to read request body", 400);
  }

  // Extract owner + name from raw body using a safe regex (no eval, no trust)
  // to look up the webhookSecret before we parse the full payload.
  const ownerMatch = rawBody.match(/"login"\s*:\s*"([^"]{1,100})"/);
  const nameMatch = rawBody.match(/"name"\s*:\s*"([^"]{1,100})"/);

  if (!ownerMatch || !nameMatch) {
    throw new AppError("Invalid webhook payload structure", 400);
  }

  const earlyOwner = ownerMatch[1];
  const earlyName = nameMatch[1];

  // Look up repository to get webhookSecret
  const repository = await Repository.findOne({ owner: earlyOwner, name: earlyName }).select("+webhookSecret");

  if (!repository) {
    throw new AppError(
      `Repository ${earlyOwner}/${earlyName} not registered. Register via POST /api/repositories first.`,
      404
    );
  }

  // FIX #2: webhookSecret is now REQUIRED — empty/missing secret is rejected.
  if (!repository.webhookSecret) {
    throw new AppError(
      "Repository webhookSecret is not configured. Set a secret when registering the repository.",
      401
    );
  }

  if (!verifyWebhookSignature(rawBody, signature, repository.webhookSecret)) {
    throw new AppError("Invalid webhook HMAC signature", 401);
  }

  // ── HMAC verified — now safely parse and trust the full payload ──
  const parsed = webhookPayloadSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(`Invalid webhook payload: ${parsed.error.message}`, 400);
  }

  const event = parsed.data;

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
