import { execFile } from "child_process";
import { promisify } from "util";
import { mkdtemp, rm, cp } from "fs/promises";
import { existsSync } from "fs";
import os from "os";
import path from "path";

const execFileAsync = promisify(execFile);
const CLONE_TIMEOUT_MS = 3 * 60 * 1000;

export interface Checkout {
    repoPath: string;
    cleanup: () => Promise<void>;
}

/**
 * Clones a repository at a specific commit SHA into a fresh temp directory
 * or copies a local path, and returns the path plus a cleanup function.
 */
export async function checkoutRepo(
    githubUrl: string,
    commitSha: string,
    githubToken?: string
): Promise<Checkout> {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "secureflow-checkout-"));

    const cleanup = async () => {
        await rm(tempDir, { recursive: true, force: true }).catch(() => {
            /* best-effort cleanup */
        });
    };

    // Check if githubUrl points to a local directory
    const cleanUrl = githubUrl.replace(/^file:\/\//i, "");
    const possibleLocalPaths = [
        cleanUrl,
        path.resolve(process.cwd(), cleanUrl),
        path.resolve(__dirname, "../../..", cleanUrl)
    ];

    for (const p of possibleLocalPaths) {
        if (existsSync(p)) {
            try {
                await cp(p, tempDir, { recursive: true });
                return { repoPath: tempDir, cleanup };
            } catch {
                // fallback to git clone
            }
        }
    }

    // Inject an auth token into the clone URL for private repos
    const cloneUrl = githubToken
        ? githubUrl.replace("https://", `https://x-access-token:${githubToken}@`)
        : githubUrl;

    try {
        await execFileAsync("git", ["clone", "--quiet", cloneUrl, tempDir], {
            timeout: CLONE_TIMEOUT_MS
        });
        if (commitSha && commitSha !== "HEAD" && commitSha.length >= 7) {
            await execFileAsync("git", ["-C", tempDir, "checkout", "--quiet", commitSha], {
                timeout: CLONE_TIMEOUT_MS
            }).catch(() => {
                /* allow scanning working tree if commit checkout fails */
            });
        }
    } catch (err: unknown) {
        await cleanup();
        const message = err instanceof Error ? err.message : "unknown error";
        const redacted = githubToken ? message.replaceAll(githubToken, "[REDACTED]") : message;
        console.error(`[checkout] Repository checkout failed: ${redacted}`);
        throw new Error(`Repository checkout failed: ${redacted}`);
    }

    return { repoPath: tempDir, cleanup };
}