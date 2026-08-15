import { Request, Response } from "express";
import { z } from "zod";
import mongoose from "mongoose";
import Finding from "../models/Finding";
import Scan from "../models/Scan";
import Repository from "../models/Repository";
import { AppError } from "../middleware/errorHandler";
import { asyncHandler } from "../utils/asyncHandler";
import { checkOllamaStatus } from "../services/ai/ollamaClient";
import { reviewFinding, generateRemediation } from "../services/ai/aiReviewerService";
import { extractCodeContext } from "../services/ai/contextExtractor";
import { computeRisk } from "../services/riskService";
import { checkoutRepo } from "../services/repoCheckoutService";

const ALLOWED_STATUSES = [
  "OPEN",
  "CONFIRMED",
  "LIKELY",
  "NEEDS_REVIEW",
  "FALSE_POSITIVE",
  "REMEDIATED",
  "RESOLVED",
  "IGNORED",
  "open",
  "false_positive",
  "confirmed",
  "remediated"
] as const;

const listFindingsQuerySchema = z.object({
  scanId: z.string().optional(),
  repositoryId: z.string().optional(),
  category: z.enum([
    "SAST",
    "SCA",
    "SECRETS",
    "AI_SECURITY",
    "CONTAINER",
    "IAC",
    "CI_CD",
    "sast",
    "sca",
    "secrets",
    "ai_security",
    "container",
    "iac",
    "ci_cd"
  ]).optional(),
  tool: z.string().optional(),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  status: z.string().optional()
});

/**
 * GET /api/findings?scanId=&repositoryId=&category=&tool=&severity=&status=
 */
export const listFindings = asyncHandler(async (req: Request, res: Response) => {
  const parsed = listFindingsQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    throw new AppError(`Invalid query params: ${parsed.error.message}`, 400);
  }

  const { scanId, repositoryId, category, tool, severity, status } = parsed.data;
  const filter: Record<string, unknown> = {};

  if (scanId) {
    if (!mongoose.isValidObjectId(scanId)) throw new AppError("Invalid scanId", 400);
    filter.scanId = scanId;
  }
  if (repositoryId) {
    if (!mongoose.isValidObjectId(repositoryId)) throw new AppError("Invalid repositoryId", 400);
    filter.repositoryId = repositoryId;
  }
  if (category) {
    filter.category = category.toUpperCase();
  }
  if (tool) {
    filter.tool = tool.toLowerCase();
  }
  if (severity) filter.severity = severity.toLowerCase();
  if (status) {
    // Match either exact or uppercase/lowercase equivalent
    filter.$or = [
      { status: status },
      { status: status.toUpperCase() },
      { status: status.toLowerCase() }
    ];
  }

  const findings = await Finding.find(filter)
    .populate("repositoryId", "name owner githubUrl defaultBranch")
    .populate("scanId", "commitSha status gateResult startedAt completedAt scannerVersion")
    .sort({ createdAt: -1 })
    .limit(200);
  res.status(200).json({ success: true, data: findings });
});

/**
 * GET /api/findings/ollama-status
 */
export const getOllamaStatusHandler = asyncHandler(async (_req: Request, res: Response) => {
  const status = await checkOllamaStatus();
  res.status(200).json({ success: true, data: status });
});

/**
 * GET /api/findings/:id
 */
export const getFinding = asyncHandler(async (req: Request, res: Response) => {
  const finding = await Finding.findById(req.params.id)
    .populate("repositoryId", "name owner githubUrl defaultBranch")
    .populate("scanId", "commitSha status gateResult startedAt completedAt scannerVersion");
  if (!finding) {
    throw new AppError("Finding not found", 404);
  }
  res.status(200).json({ success: true, data: finding });
});


const updateStatusSchema = z.object({
  status: z.enum(ALLOWED_STATUSES)
});

/**
 * PATCH /api/findings/:id
 */
export const updateFindingStatus = asyncHandler(async (req: Request, res: Response) => {
  const parsed = updateStatusSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(`Invalid status payload: ${parsed.error.message}`, 400);
  }

  const normalizedStatus = parsed.data.status.toUpperCase();

  const finding = await Finding.findByIdAndUpdate(
    req.params.id,
    { status: normalizedStatus },
    { new: true }
  );


  if (!finding) {
    throw new AppError("Finding not found", 404);
  }

  res.status(200).json({ success: true, data: finding });
});

/**
 * POST /api/findings/:id/ai-review
 * Re-runs Ollama AI review on a specific finding.
 * Clones the original repository at the finding's commit SHA to ensure
 * AI context extraction reads the correct file, not a stale local copy.
 */
export const triggerAiReview = asyncHandler(async (req: Request, res: Response) => {
  const finding = await Finding.findById(req.params.id);
  if (!finding) {
    throw new AppError("Finding not found", 404);
  }

  // Resolve the original repo URL and commit SHA from the finding's scan
  const scan = await Scan.findById(finding.scanId);
  if (!scan) {
    throw new AppError("Associated scan not found", 404);
  }

  const repository = await Repository.findById(finding.repositoryId);
  if (!repository) {
    throw new AppError("Associated repository not found", 404);
  }

  const githubToken = process.env.GITHUB_TOKEN || process.env.GITHUB_APP_TOKEN;
  const checkout = await checkoutRepo(repository.githubUrl, scan.commitSha, githubToken);

  try {
    const context = await extractCodeContext(checkout.repoPath, finding.file, finding.line);

    const nf = {
      tool: finding.tool as "semgrep" | "gitleaks" | "trivy",
      file: finding.file,
      line: finding.line,
      ruleId: finding.ruleId,
      codeSnippet: finding.codeSnippet,
      secretRef: finding.secretRef || null,
      severity: finding.severity as "critical" | "high" | "medium" | "low"
    };

    if (!context) {
      throw new AppError(`File ${finding.file} not found in repository at commit ${scan.commitSha}`, 404);
    }

    const review = await reviewFinding(nf, context);
    const remediation = await generateRemediation(nf, context, review);
    const risk = computeRisk(nf, review);

    finding.ai = {
      isRealVulnerability: review.isRealVulnerability,
      confidence: review.confidence,
      attackScenario: review.attackScenario,
      cwe: review.cwe,
      owasp: review.owasp,
      exploitability: review.exploitability,
      remediation,
      reviewFailed: review.reviewFailed
    };
    finding.risk = risk;

    await finding.save();

    res.status(200).json({ success: true, data: finding });
  } finally {
    await checkout.cleanup();
  }
});