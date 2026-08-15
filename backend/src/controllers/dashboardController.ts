import { Request, Response } from "express";
import mongoose from "mongoose";
import Finding from "../models/Finding";
import Scan from "../models/Scan";
import Repository from "../models/Repository";
import { asyncHandler } from "../utils/asyncHandler";

/**
 * GET /api/dashboard/stats?repositoryId=&scanId=
 *
 * Returns aggregated metrics powering the Dashboard page. Every field is
 * designed so the frontend can plug it directly into a Recharts component
 * without further transformation.
 *
 * Optional filters:
 *   - repositoryId: scope all stats to a single repository
 *   - scanId: scope all stats to a single scan
 */
export const getDashboardStats = asyncHandler(async (req: Request, res: Response) => {
  // Build a base filter for findings based on optional query parameters
  const findingFilter: Record<string, unknown> = {};
  const scanFilter: Record<string, unknown> = {};

  if (req.query.repositoryId && mongoose.isValidObjectId(req.query.repositoryId as string)) {
    const repoObjectId = new mongoose.Types.ObjectId(req.query.repositoryId as string);
    findingFilter.repositoryId = repoObjectId;
    scanFilter.repositoryId = repoObjectId;
  }
  if (req.query.scanId && mongoose.isValidObjectId(req.query.scanId as string)) {
    const scanObjectId = new mongoose.Types.ObjectId(req.query.scanId as string);
    findingFilter.scanId = scanObjectId;
  }

  const findingMatchStage = Object.keys(findingFilter).length > 0 ? [{ $match: findingFilter }] : [];

  const [
    totalRepositories,
    totalScans,
    totalFindings,
    severityAgg,
    categoryAgg,
    toolAgg,
    statusAgg,
    topFiles,
    recentScans,
    riskScoreAgg
  ] = await Promise.all([
    Repository.countDocuments(),
    Scan.countDocuments(scanFilter),
    Finding.countDocuments(findingFilter),

    // Severity distribution for PieChart
    Finding.aggregate([
      ...findingMatchStage,
      { $group: { _id: "$severity", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]),

    // Category distribution (SAST vs SCA vs SECRETS)
    Finding.aggregate([
      ...findingMatchStage,
      { $group: { _id: "$category", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]),

    // Tool distribution for BarChart
    Finding.aggregate([
      ...findingMatchStage,
      { $group: { _id: "$tool", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]),

    // Status distribution
    Finding.aggregate([
      ...findingMatchStage,
      { $group: { _id: "$status", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]),

    // Top 10 most vulnerable files
    Finding.aggregate([
      ...findingMatchStage,
      { $group: {
        _id: "$file",
        count: { $sum: 1 },
        maxRisk: { $max: "$risk.score" },
        severities: { $push: "$severity" }
      }},
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]),

    // Recent 20 scans for timeline chart
    Scan.find(scanFilter)
      .sort({ startedAt: -1 })
      .limit(20)
      .select("prNumber commitSha status gateResult summary startedAt completedAt")
      .lean(),

    // Overall risk score stats
    Finding.aggregate([
      ...findingMatchStage,
      { $match: { "risk.score": { $exists: true } } },
      { $group: {
        _id: null,
        avgRisk: { $avg: "$risk.score" },
        maxRisk: { $max: "$risk.score" },
        minRisk: { $min: "$risk.score" },
        totalRiskFindings: { $sum: 1 }
      }}
    ])
  ]);

  // Build severity map with guaranteed keys
  const severityMap: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of severityAgg) {
    severityMap[item._id] = item.count;
  }

  // Build category map
  const categoryMap: Record<string, number> = { SAST: 0, SCA: 0, SECRETS: 0, AI_SECURITY: 0, CONTAINER: 0, IAC: 0, CI_CD: 0 };
  for (const item of categoryAgg) {
    const key = String(item._id || "SAST").toUpperCase();
    if (categoryMap[key] !== undefined) {
      categoryMap[key] += item.count;
    } else {
      categoryMap[key] = item.count;
    }
  }

  // Build tool map
  const toolMap: Record<string, number> = {
    semgrep: 0,
    gitleaks: 0,
    trivy: 0,
    osv: 0,
    "secret-scanner": 0,
    "ai-security-scanner": 0,
    "container-scanner": 0,
    "iac-scanner": 0,
    "trivy-config": 0,
    "cicd-scanner": 0
  };
  for (const item of toolAgg) {
    toolMap[item._id] = item.count;
  }

  // Build status map with normalization
  const statusMap: Record<string, number> = {
    open: 0,
    confirmed: 0,
    likely: 0,
    needs_review: 0,
    false_positive: 0,
    remediated: 0,
    resolved: 0
  };
  for (const item of statusAgg) {
    const key = String(item._id || "").toLowerCase();
    if (statusMap[key] !== undefined) {
      statusMap[key] += item.count;
    } else {
      statusMap[key] = item.count;
    }
  }

  // Compute open, remediated, false positives from real database findings
  const openFindingsCount = (statusMap.open || 0) + (statusMap.confirmed || 0) + (statusMap.likely || 0) + (statusMap.needs_review || 0);
  const remediatedFindingsCount = (statusMap.remediated || 0) + (statusMap.resolved || 0);
  const falsePositivesCount = statusMap.false_positive || 0;

  // Compute security score (0-100, where 100 = perfectly secure)
  const riskStats = riskScoreAgg[0] || { avgRisk: 0, maxRisk: 0, minRisk: 0, totalRiskFindings: 0 };
  const openCritical = severityMap.critical || 0;
  const openHigh = severityMap.high || 0;
  const openMedium = severityMap.medium || 0;
  let securityScore = 100;
  securityScore -= openCritical * 15;
  securityScore -= openHigh * 8;
  securityScore -= openMedium * 3;
  securityScore = Math.max(0, Math.min(100, securityScore));

  // Gate pass rate from real scans
  const passedScans = recentScans.filter((s: any) => s.gateResult === "pass").length;
  const completedScans = recentScans.filter((s: any) => s.status === "completed" || s.gateResult).length;
  const gatePassRate = completedScans > 0 ? Math.round((passedScans / completedScans) * 100) : (totalScans > 0 ? 100 : 100);

  // Scan timeline & severity trend data for AreaChart (reversed so oldest is first)
  const scanTimeline = [...recentScans].reverse().map((s: any) => ({
    date: s.startedAt,
    critical: s.summary?.critical || 0,
    high: s.summary?.high || 0,
    medium: s.summary?.medium || 0,
    low: s.summary?.low || 0,
    total: s.summary?.total || 0,
    gateResult: s.gateResult,
    prNumber: s.prNumber
  }));

  // Vulnerability trend data
  const vulnerabilityTrend = scanTimeline.map((item, idx) => ({
    scanIndex: idx + 1,
    date: item.date,
    totalFindings: item.total,
    critical: item.critical,
    high: item.high,
    gateResult: item.gateResult
  }));

  // Severity chart data (for Recharts PieChart)
  const SEVERITY_COLORS: Record<string, string> = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#22c55e"
  };
  const severityChartData = Object.entries(severityMap)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name, value, fill: SEVERITY_COLORS[name] || "#6b7280" }));

  // Category chart data
  const CATEGORY_COLORS: Record<string, string> = {
    SAST: "#6366f1",
    AI_SECURITY: "#a855f7",
    SCA: "#06b6d4",
    SECRETS: "#f43f5e",
    CONTAINER: "#38bdf8",
    IAC: "#f59e0b",
    CI_CD: "#10b981"
  };
  const categoryChartData = Object.entries(categoryMap).map(([name, value]) => ({
    name,
    value,
    fill: CATEGORY_COLORS[name] || "#6b7280"
  }));

  // Tool chart data (for Recharts BarChart)
  const TOOL_COLORS: Record<string, string> = {
    semgrep: "#8b5cf6",
    "ai-security-scanner": "#a855f7",
    gitleaks: "#ec4899",
    "secret-scanner": "#f43f5e",
    trivy: "#06b6d4",
    osv: "#10b981",
    "container-scanner": "#38bdf8",
    "iac-scanner": "#f59e0b",
    "trivy-config": "#3b82f6",
    "cicd-scanner": "#10b981"
  };
  const toolChartData = Object.entries(toolMap)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({
      name, value, fill: TOOL_COLORS[name] || "#6b7280"
    }));

  res.status(200).json({
    success: true,
    data: {
      overview: {
        totalRepositories,
        totalScans,
        totalFindings,
        critical: severityMap.critical || 0,
        high: severityMap.high || 0,
        medium: severityMap.medium || 0,
        low: severityMap.low || 0,
        averageRisk: Math.round(riskStats.avgRisk || 0),
        openFindings: openFindingsCount,
        remediatedFindings: remediatedFindingsCount,
        falsePositives: falsePositivesCount,
        sastCount: categoryMap.SAST || 0,
        aiSecurityCount: categoryMap.AI_SECURITY || 0,
        scaCount: categoryMap.SCA || 0,
        secretsCount: categoryMap.SECRETS || 0,
        containerCount: categoryMap.CONTAINER || 0,
        iacCount: categoryMap.IAC || 0,
        cicdCount: categoryMap.CI_CD || 0,
        securityScore,
        gatePassRate
      },
      severity: severityMap,
      severityChartData,
      severityTrend: scanTimeline,
      vulnerabilityTrend,
      categoryDistribution: categoryMap,
      categoryChartData,
      toolDistribution: toolMap,
      toolChartData,
      statusDistribution: statusMap,
      topVulnerableFiles: topFiles.map((f: any) => ({
        file: f._id,
        findingCount: f.count,
        maxRiskScore: f.maxRisk || 0,
        criticalCount: f.severities.filter((s: string) => s === "critical").length,
        highCount: f.severities.filter((s: string) => s === "high").length
      })),
      scanTimeline,
      riskStats: {
        averageRisk: Math.round(riskStats.avgRisk || 0),
        maxRisk: riskStats.maxRisk || 0,
        totalAssessedFindings: riskStats.totalRiskFindings || 0
      },
      recentScans: recentScans.slice(0, 8)
    }
  });
});
