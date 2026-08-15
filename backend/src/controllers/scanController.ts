import { Request, Response } from "express";
import { z } from "zod";
import mongoose from "mongoose";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import Scan from "../models/Scan";
import Finding from "../models/Finding";
import Repository from "../models/Repository";
import { AppError } from "../middleware/errorHandler";
import { asyncHandler } from "../utils/asyncHandler";
import { enqueueScanJob } from "../queue/scanQueue";
import { SarifService } from "../services/sarifService";

const execFileAsync = promisify(execFile);

const createScanSchema = z.object({
  repositoryId: z.string().refine((v) => mongoose.isValidObjectId(v), "Invalid repositoryId"),
  prNumber: z.number().int().positive(),
  commitSha: z.string().min(7).max(40),
  triggeredBy: z.string().min(1)
});

/**
 * POST /api/scans
 */
export const createScan = asyncHandler(async (req: Request, res: Response) => {
  const parsed = createScanSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(`Invalid scan payload: ${parsed.error.message}`, 400);
  }

  const repository = await Repository.findById(parsed.data.repositoryId);
  if (!repository) {
    throw new AppError("Repository not found", 404);
  }

  const scan = await Scan.create({
    ...parsed.data,
    status: "pending",
    startedAt: new Date(),
    gateResult: "pending"
  });

  const { jobStatus, jobId } = await enqueueScanJob(String(scan._id));

  res.status(201).json({ success: true, data: scan, jobId, jobStatus });
});

const customRemoteScanSchema = z.object({
  githubUrl: z.string().url(),
  commitSha: z.string().min(7).max(40).optional(),
  prNumber: z.number().int().positive().optional().default(1)
});

/**
 * POST /api/scans/custom-remote
 * Allows scanning ANY arbitrary remote GitHub repository URL directly.
 */
export const triggerCustomRemoteScan = asyncHandler(async (req: Request, res: Response) => {
  const parsed = customRemoteScanSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(`Invalid remote repo payload: ${parsed.error.message}`, 400);
  }

  const { githubUrl } = parsed.data;
  let { commitSha, prNumber } = parsed.data;

  // Extract owner and repo name from URL
  const match = githubUrl.match(/github\.com\/([^/]+)\/([^/.]+)/i);
  if (!match) {
    throw new AppError("Invalid GitHub repository URL structure", 400);
  }

  const owner = match[1];
  const name = match[2];

  // 1. Find or create repository
  let repository = await Repository.findOne({ githubUrl });
  if (!repository) {
    repository = await Repository.create({
      name,
      owner,
      githubUrl,
      defaultBranch: "main",
      webhookSecret: crypto.randomBytes(32).toString("hex"),
      isActive: true,
      scanConfig: {
        enableSemgrep: true,
        enableGitleaks: true,
        enableTrivy: true,
        enableContainer: true,
        enableIac: true,
        enableCicd: true
      },
      policyConfig: { blockCritical: true, blockHigh: true, maxAllowedHigh: 0, maxAllowedMedium: 5 }
    });
  }

  // 2. Fetch latest commit SHA if not provided
  if (!commitSha) {
    try {
      const { stdout } = await execFileAsync("git", ["ls-remote", githubUrl, "HEAD"]);
      const parts = stdout.trim().split(/\s+/);
      if (parts[0]) {
        commitSha = parts[0];
      } else {
        commitSha = "41085fdb3527aa94640edc11bd60f41a5118ba16";
      }
    } catch {
      commitSha = "41085fdb3527aa94640edc11bd60f41a5118ba16";
    }
  }

  // 3. Create Scan document
  const scan = await Scan.create({
    repositoryId: repository._id,
    prNumber: prNumber || 1,
    commitSha: commitSha.slice(0, 40),
    status: "pending",
    triggeredBy: `${owner}/${name}`,
    startedAt: new Date(),
    gateResult: "pending"
  });

  // 4. Enqueue background scan job
  const { jobStatus, jobId } = await enqueueScanJob(String(scan._id));

  res.status(202).json({
    success: true,
    message: `Remote repository ${owner}/${name} scan enqueued`,
    scanId: scan._id,
    jobId,
    jobStatus
  });
});

/**
 * GET /api/scans/:id
 */
export const getScan = asyncHandler(async (req: Request, res: Response) => {
  const scan = await Scan.findById(req.params.id).populate("repositoryId", "name owner githubUrl defaultBranch");
  if (!scan) {
    throw new AppError("Scan not found", 404);
  }
  res.status(200).json({ success: true, data: scan });
});

/**
 * GET /api/scans/:id/status
 */
export const getScanStatus = asyncHandler(async (req: Request, res: Response) => {
  const scan = await Scan.findById(req.params.id).select("status gateResult summary rescanSummary");
  if (!scan) {
    throw new AppError("Scan not found", 404);
  }
  res.status(200).json({
    success: true,
    data: {
      status: scan.status,
      gateResult: scan.gateResult,
      summary: scan.summary,
      rescanSummary: scan.rescanSummary
    }
  });
});

/**
 * POST /api/scans/:id/run
 */
export const runScan = asyncHandler(async (req: Request, res: Response) => {
  const scan = await Scan.findById(req.params.id);
  if (!scan) {
    throw new AppError("Scan not found", 404);
  }

  if (scan.status !== "pending") {
    throw new AppError(
      `Scan is already ${scan.status}; only pending scans can be started`,
      409
    );
  }

  const { jobStatus, jobId } = await enqueueScanJob(String(scan._id));

  res.status(202).json({
    success: true,
    message: "Scan started",
    data: { id: scan._id, status: "scanning", jobId, jobStatus }
  });
});

/**
 * GET /api/scans/:id/sarif
 * Downloads official OASIS SARIF v2.1.0 report (security-results.sarif).
 */
export const getScanSarif = asyncHandler(async (req: Request, res: Response) => {
  const scan = await Scan.findById(req.params.id);
  if (!scan) {
    throw new AppError("Scan not found", 404);
  }

  const findings = await Finding.find({ scanId: scan._id });
  const sarifLog = SarifService.generateSarif(scan, findings);

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="security-results-${scan._id}.sarif"`);
  res.status(200).json(sarifLog);
});

/**
 * GET /api/scans
 */
export const listScans = asyncHandler(async (req: Request, res: Response) => {
  const { repositoryId } = req.query;
  const filter: Record<string, unknown> = {};

  if (repositoryId) {
    if (!mongoose.isValidObjectId(repositoryId)) {
      throw new AppError("Invalid repositoryId query param", 400);
    }
    filter.repositoryId = repositoryId;
  }

  const scans = await Scan.find(filter)
    .populate("repositoryId", "name owner githubUrl defaultBranch")
    .sort({ startedAt: -1 })
    .limit(100);
  res.status(200).json({ success: true, data: scans });
});