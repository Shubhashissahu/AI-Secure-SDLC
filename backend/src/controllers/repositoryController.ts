import { Request, Response } from "express";
import crypto from "crypto";
import { z } from "zod";
import Repository from "../models/Repository";
import Scan from "../models/Scan";
import Finding from "../models/Finding";
import AiReview from "../models/AIReview";
import ScanJob from "../models/ScanJob";
import { AppError } from "../middleware/errorHandler";
import { asyncHandler } from "../utils/asyncHandler";

const createRepositorySchema = z.object({
  name: z.string().min(1).max(200),
  owner: z.string().min(1).max(200),
  githubUrl: z.string().url(),
  defaultBranch: z.string().min(1).max(100).optional()
});

/**
 * POST /api/repositories
 * Registers a new repository. The webhook secret is generated server-side
 * and returned ONCE in this response only — it is never retrievable again
 * via GET (see Repository model's select:false), so the caller must copy it
 * into the repo's GitHub webhook config immediately.
 */
export const createRepository = asyncHandler(async (req: Request, res: Response) => {
  const parsed = createRepositorySchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(`Invalid repository payload: ${parsed.error.message}`, 400);
  }

  const webhookSecret = crypto.randomBytes(32).toString("hex");
  const existing = await Repository.findOne({ githubUrl: parsed.data.githubUrl });

  if (existing) {
    existing.name = parsed.data.name;
    existing.owner = parsed.data.owner;
    if (parsed.data.defaultBranch) {
      existing.defaultBranch = parsed.data.defaultBranch;
    }
    existing.webhookSecret = webhookSecret;
    await existing.save();

    res.status(200).json({
      success: true,
      message: "Repository updated successfully",
      data: {
        id: existing._id,
        name: existing.name,
        owner: existing.owner,
        githubUrl: existing.githubUrl,
        defaultBranch: existing.defaultBranch,
        webhookSecret
      }
    });
    return;
  }

  const repository = await Repository.create({
    ...parsed.data,
    webhookSecret
  });

  res.status(201).json({
    success: true,
    data: {
      id: repository._id,
      name: repository.name,
      owner: repository.owner,
      githubUrl: repository.githubUrl,
      defaultBranch: repository.defaultBranch,
      webhookSecret
    }
  });
});

/**
 * GET /api/repositories
 * GET /api/repositories?githubUrl=https://github.com/org/repo
 * Lists registered repositories, optionally filtered to an exact githubUrl
 * match. The githubUrl filter exists specifically so the CI workflow can
 * resolve its own repositoryId at runtime (see
 * .github/workflows/security-review.yml) instead of requiring a hardcoded
 * per-repo secret. webhookSecret is excluded by default (select:false on
 * the model), so no extra filtering needed here.
 */
export const listRepositories = asyncHandler(async (req: Request, res: Response) => {
  const { githubUrl } = req.query;
  const filter: Record<string, unknown> = {};

  if (typeof githubUrl === "string" && githubUrl.length > 0) {
    filter.githubUrl = githubUrl;
  }

  const repositories = await Repository.find(filter).sort({ createdAt: -1 });
  res.status(200).json({ success: true, data: repositories });
});

/**
 * GET /api/repositories/:id
 */
export const getRepository = asyncHandler(async (req: Request, res: Response) => {
  const repository = await Repository.findById(req.params.id);
  if (!repository) {
    throw new AppError("Repository not found", 404);
  }
  res.status(200).json({ success: true, data: repository });
});

/**
 * PATCH /api/repositories/:id
 */
export const updateRepository = asyncHandler(async (req: Request, res: Response) => {
  const repository = await Repository.findById(req.params.id);
  if (!repository) {
    throw new AppError("Repository not found", 404);
  }

  if (req.body.name) repository.name = req.body.name;
  if (req.body.defaultBranch) repository.defaultBranch = req.body.defaultBranch;
  if (req.body.isActive !== undefined) repository.isActive = req.body.isActive;

  if (req.body.scanConfig) {
    repository.scanConfig = {
      ...repository.scanConfig,
      ...req.body.scanConfig
    };
  }

  if (req.body.policyConfig) {
    repository.policyConfig = {
      ...repository.policyConfig,
      ...req.body.policyConfig
    };
  }

  await repository.save();
  res.status(200).json({ success: true, message: "Repository updated successfully", data: repository });
});

/**
 * DELETE /api/repositories/:id
 */
export const deleteRepository = asyncHandler(async (req: Request, res: Response) => {
  const repository = await Repository.findById(req.params.id);
  if (!repository) {
    throw new AppError("Repository not found", 404);
  }

  // Find all scans associated with this repository to delete their related records
  const scans = await Scan.find({ repositoryId: repository._id }).select("_id");
  const scanIds = scans.map(s => s._id);

  // Cascading deletes
  if (scanIds.length > 0) {
    await ScanJob.deleteMany({ scanId: { $in: scanIds } });
    await AiReview.deleteMany({ scanId: { $in: scanIds } });
  }
  await Finding.deleteMany({ repositoryId: repository._id });
  await Scan.deleteMany({ repositoryId: repository._id });
  await Repository.findByIdAndDelete(req.params.id);

  res.status(200).json({ success: true, message: "Repository and all related data deleted successfully" });
});