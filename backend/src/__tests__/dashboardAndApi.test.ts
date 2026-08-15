import { Request, Response } from "express";
import { getDashboardStats } from "../controllers/dashboardController";
import { listRepositories } from "../controllers/repositoryController";
import { listScans } from "../controllers/scanController";
import { listFindings } from "../controllers/findingController";
import Repository from "../models/Repository";
import Scan from "../models/Scan";
import Finding from "../models/Finding";

describe("Dashboard & REST API Unit and Aggregation Test Suite", () => {
  function createMockResponse() {
    const res: Partial<Response> = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    return res as Response;
  }

  test("GET /api/dashboard/stats & /api/dashboard returns correct aggregated metrics from database", async () => {
    // Mock DB counts and aggregations
    jest.spyOn(Repository, "countDocuments").mockResolvedValueOnce(3 as any);
    jest.spyOn(Scan, "countDocuments").mockResolvedValueOnce(5 as any);
    jest.spyOn(Finding, "countDocuments").mockResolvedValueOnce(12 as any);

    jest.spyOn(Finding, "aggregate")
      .mockResolvedValueOnce([
        { _id: "critical", count: 2 },
        { _id: "high", count: 6 },
        { _id: "medium", count: 3 },
        { _id: "low", count: 1 }
      ] as any) // severityAgg
      .mockResolvedValueOnce([
        { _id: "SAST", count: 5 },
        { _id: "AI_SECURITY", count: 3 },
        { _id: "SECRETS", count: 2 },
        { _id: "SCA", count: 2 }
      ] as any) // categoryAgg
      .mockResolvedValueOnce([
        { _id: "semgrep", count: 5 },
        { _id: "ai-security-scanner", count: 3 },
        { _id: "gitleaks", count: 2 }
      ] as any) // toolAgg
      .mockResolvedValueOnce([
        { _id: "open", count: 10 },
        { _id: "remediated", count: 2 }
      ] as any) // statusAgg
      .mockResolvedValueOnce([
        { _id: "src/login.java", count: 3, maxRisk: 80, severities: ["high", "high", "critical"] }
      ] as any) // topFiles
      .mockResolvedValueOnce([
        { _id: null, avgRisk: 72, maxRisk: 95, minRisk: 30, totalRiskFindings: 12 }
      ] as any); // riskScoreAgg

    jest.spyOn(Scan, "find").mockReturnValue({
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue([
        {
          _id: "scan123",
          prNumber: 1,
          commitSha: "abc12345",
          status: "completed",
          gateResult: "pass",
          summary: { total: 12, critical: 2, high: 6, medium: 3, low: 1 },
          startedAt: new Date()
        }
      ])
    } as any);

    const req = { query: {} } as Request;
    const res = createMockResponse();

    await new Promise<void>((resolve, reject) => {
      res.json = jest.fn((_data) => {
        resolve();
        return res;
      });
      const next = jest.fn((err) => {
        if (err) reject(err);
        else resolve();
      });
      getDashboardStats(req, res, next);
    });

    expect(res.status).toHaveBeenCalledWith(200);
    const jsonCall = (res.json as jest.Mock).mock.calls[0][0];
    expect(jsonCall.success).toBe(true);
    expect(jsonCall.data.overview.totalRepositories).toBe(3);
    expect(jsonCall.data.overview.totalScans).toBe(5);
    expect(jsonCall.data.overview.totalFindings).toBe(12);
    expect(jsonCall.data.overview.critical).toBe(2);
    expect(jsonCall.data.overview.high).toBe(6);
    expect(jsonCall.data.overview.sastCount).toBe(5);
    expect(jsonCall.data.overview.aiSecurityCount).toBe(3);
    expect(jsonCall.data.overview.secretsCount).toBe(2);
  });

  test("GET /api/repositories returns repository list", async () => {
    jest.spyOn(Repository, "find").mockReturnValue({
      sort: jest.fn().mockResolvedValue([
        { _id: "repo1", name: "app", owner: "org", githubUrl: "https://github.com/org/app" }
      ])
    } as any);

    const req = { query: {} } as Request;
    const res = createMockResponse();

    await new Promise<void>((resolve, reject) => {
      res.json = jest.fn((_data) => {
        resolve();
        return res;
      });
      const next = jest.fn((err) => {
        if (err) reject(err);
        else resolve();
      });
      listRepositories(req, res, next);
    });

    expect(res.status).toHaveBeenCalledWith(200);
    const jsonCall = (res.json as jest.Mock).mock.calls[0][0];
    expect(jsonCall.success).toBe(true);
    expect(jsonCall.data.length).toBe(1);
    expect(jsonCall.data[0].name).toBe("app");
  });

  test("GET /api/scans returns scans list", async () => {
    jest.spyOn(Scan, "find").mockReturnValue({
      populate: jest.fn().mockReturnThis(),
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockResolvedValue([
        { _id: "scan1", commitSha: "abc1234", status: "completed", summary: { total: 4 } }
      ])
    } as any);

    const req = { query: {} } as Request;
    const res = createMockResponse();

    await new Promise<void>((resolve, reject) => {
      res.json = jest.fn((_data) => {
        resolve();
        return res;
      });
      const next = jest.fn((err) => {
        if (err) reject(err);
        else resolve();
      });
      listScans(req, res, next);
    });

    expect(res.status).toHaveBeenCalledWith(200);
    const jsonCall = (res.json as jest.Mock).mock.calls[0][0];
    expect(jsonCall.success).toBe(true);
    expect(jsonCall.data.length).toBe(1);
  });

  test("GET /api/findings returns findings list filtered by category", async () => {
    jest.spyOn(Finding, "find").mockReturnValue({
      populate: jest.fn().mockReturnThis(),
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockResolvedValue([
        {
          _id: "find1",
          category: "AI_SECURITY",
          ruleId: "prompt-injection",
          severity: "high",
          file: "python-vulnerable/prompt_injection.py"
        }
      ])
    } as any);

    const req = { query: { category: "AI_SECURITY" } } as unknown as Request;
    const res = createMockResponse();

    await new Promise<void>((resolve, reject) => {
      res.json = jest.fn((_data) => {
        resolve();
        return res;
      });
      const next = jest.fn((err) => {
        if (err) reject(err);
        else resolve();
      });
      listFindings(req, res, next);
    });

    expect(res.status).toHaveBeenCalledWith(200);
    const jsonCall = (res.json as jest.Mock).mock.calls[0][0];
    expect(jsonCall.success).toBe(true);
    expect(jsonCall.data.length).toBe(1);
    expect(jsonCall.data[0].category).toBe("AI_SECURITY");
  });
});
