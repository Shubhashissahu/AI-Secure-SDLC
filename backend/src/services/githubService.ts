import axios, { AxiosInstance } from "axios";
import { gzipSync } from "zlib";

export interface GitHubPullRequest {
  number: number;
  title: string;
  body: string;
  head: {
    sha: string;
    ref: string;
    repo: {
      name: string;
      owner: {
        login: string;
      };
      html_url: string;
    };
  };
  base: {
    ref: string;
  };
}

export interface GitHubCheckRun {
  name: string;
  head_sha: string;
  status: "queued" | "in_progress" | "completed";
  conclusion?: "success" | "failure" | "neutral" | "cancelled" | "timed_out" | "action_required";
  output: {
    title: string;
    summary: string;
    text?: string;
  };
}

/**
 * GitHub API integration service.
 * Handles PR status checks, comments, Check Runs, Commit Statuses, and webhook management.
 */
export class GitHubService {
  private client: AxiosInstance;

  constructor(githubToken: string) {
    this.client = axios.create({
      baseURL: "https://api.github.com",
      headers: {
        Authorization: `token ${githubToken}`,
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "ai-secure-sdlc"
      }
    });
  }

  /**
   * Create or update a check run (CI status indicator in GitHub PR).
   */
  async createCheckRun(
    owner: string,
    repo: string,
    headSha: string,
    checkRun: GitHubCheckRun
  ): Promise<void> {
    try {
      await this.client.post(`/repos/${owner}/${repo}/check-runs`, {
        name: checkRun.name,
        head_sha: headSha,
        status: checkRun.status,
        conclusion: checkRun.conclusion,
        output: checkRun.output
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[GitHubService] Failed to create check run: ${msg}`);
    }
  }

  /**
   * Post commit status check.
   */
  async createCommitStatus(
    owner: string,
    repo: string,
    sha: string,
    state: "pending" | "success" | "failure" | "error",
    description: string,
    targetUrl?: string
  ): Promise<void> {
    try {
      await this.client.post(`/repos/${owner}/${repo}/statuses/${sha}`, {
        state,
        description,
        context: "ai-secure-sdlc/security-gate",
        target_url: targetUrl
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[GitHubService] Failed to create commit status: ${msg}`);
    }
  }

  /**
   * Post a comment on a PR with findings summary and remediation advice.
   */
  async commentOnPR(
    owner: string,
    repo: string,
    prNumber: number,
    body: string
  ): Promise<void> {
    try {
      await this.client.post(
        `/repos/${owner}/${repo}/issues/${prNumber}/comments`,
        { body }
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[GitHubService] Failed to post PR comment: ${msg}`);
    }
  }

  /**
   * Upload SARIF results to GitHub Code Scanning API.
   */
  async uploadSARIF(
    owner: string,
    repo: string,
    commitSha: string,
    ref: string,
    sarifContent: string
  ): Promise<void> {
    try {
      // FIX #3: GitHub Code Scanning API requires gzip-compressed SARIF,
      // then base64-encoded. Previously only base64 was applied (no gzip).
      const gzipped = gzipSync(Buffer.from(sarifContent, "utf-8"));
      const zippedBuffer = gzipped.toString("base64");
      await this.client.post(`/repos/${owner}/${repo}/code-scanning/sarifs`, {
        commit_sha: commitSha,
        ref,
        sarif: zippedBuffer,
        tool_name: "ai-secure-sdlc"
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[GitHubService] SARIF upload notice: ${msg}`);
    }
  }

  /**
   * Get PR details for context.
   */
  async getPullRequest(
    owner: string,
    repo: string,
    prNumber: number
  ): Promise<GitHubPullRequest> {
    const response = await this.client.get<GitHubPullRequest>(
      `/repos/${owner}/${repo}/pulls/${prNumber}`
    );
    return response.data;
  }

  /**
   * Create/update webhook for PR events.
   */
  async createWebhook(
    owner: string,
    repo: string,
    webhookUrl: string,
    secret: string
  ): Promise<string> {
    const response = await this.client.post(
      `/repos/${owner}/${repo}/hooks`,
      {
        name: "web",
        active: true,
        events: ["pull_request"],
        config: {
          url: webhookUrl,
          content_type: "json",
          secret,
          insecure_ssl: "0"
        }
      }
    );
    return response.data.id;
  }
}
