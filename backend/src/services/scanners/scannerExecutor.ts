import { execFile, ChildProcess } from "child_process";

export interface ExecutionOptions {
  timeoutMs: number;
  maxRetries?: number;
  cwd?: string;
  maxBuffer?: number;
  allowedExitCodes?: number[];
  env?: NodeJS.ProcessEnv;
}

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
}

/**
 * Utility function to execute a CLI tool safely with timeout, isolated process cleanup,
 * retry mechanisms, and structured output.
 */
export async function executeScannerProcess(
  toolName: string,
  command: string,
  args: string[],
  options: ExecutionOptions
): Promise<ExecutionResult> {
  const maxRetries = options.maxRetries ?? 1;
  const timeoutMs = options.timeoutMs;
  const allowedExitCodes = options.allowedExitCodes ?? [0];
  const maxBuffer = options.maxBuffer ?? 1024 * 1024 * 50; // 50MB default

  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    const startTime = Date.now();
    try {
      if (attempt > 1) {
        console.warn(`[${toolName}] Retrying execution (attempt ${attempt}/${maxRetries + 1})...`);
        await new Promise((resolve) => setTimeout(resolve, 500 * Math.pow(2, attempt - 2)));
      }

      const result = await runProcessSingleAttempt(command, args, {
        timeoutMs,
        cwd: options.cwd,
        maxBuffer,
        allowedExitCodes,
        env: options.env
      });

      const durationMs = Date.now() - startTime;
      console.log(`[${toolName}] Scan completed in ${durationMs}ms (exit code: ${result.exitCode})`);
      return { ...result, durationMs };
    } catch (err: unknown) {
      lastError = err instanceof Error ? err : new Error(String(err));
      // Don't retry if the CLI binary does not exist (ENOENT)
      if ((err as { code?: string }).code === "ENOENT" || lastError.message.includes("ENOENT")) {
        throw lastError;
      }
    }
  }

  throw lastError || new Error(`[${toolName}] Execution failed after ${maxRetries + 1} attempts`);
}

function runProcessSingleAttempt(
  command: string,
  args: string[],
  opts: { timeoutMs: number; cwd?: string; maxBuffer: number; allowedExitCodes: number[]; env?: NodeJS.ProcessEnv }
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    let child: ChildProcess | null = null;
    let timedOut = false;
    let forceKillTimer: NodeJS.Timeout | null = null;

    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      if (child) {
        console.warn(`[scannerExecutor] Process '${command}' timed out after ${opts.timeoutMs}ms. Terminating process...`);
        try {
          child.kill("SIGTERM");
        } catch {
          /* ignore */
        }

        forceKillTimer = setTimeout(() => {
          if (child && !child.killed) {
            console.error(`[scannerExecutor] Process '${command}' did not exit on SIGTERM. Force killing (SIGKILL)...`);
            try {
              child.kill("SIGKILL");
            } catch {
              /* ignore */
            }
          }
        }, 1500);
      }
    }, opts.timeoutMs);

    child = execFile(
      command,
      args,
      {
        cwd: opts.cwd,
        maxBuffer: opts.maxBuffer,
        windowsHide: true,
        env: opts.env || process.env
      },
      (error, stdout, stderr) => {
        clearTimeout(timeoutTimer);
        if (forceKillTimer) clearTimeout(forceKillTimer);

        if (timedOut) {
          return reject(new Error("timeout"));
        }

        if (error) {
          const errCodeStr = (error as { code?: string | number }).code;
          if (errCodeStr === "ENOENT" || error.message.includes("ENOENT")) {
            return reject(error);
          }

          const numericExitCode = typeof errCodeStr === "number" ? errCodeStr : 1;

          if (!opts.allowedExitCodes.includes(numericExitCode)) {
            if (stdout && stdout.trim().length > 0) {
              return resolve({ stdout, stderr, exitCode: numericExitCode });
            }
            return reject(error);
          }

          return resolve({ stdout, stderr, exitCode: numericExitCode });
        }

        resolve({ stdout, stderr, exitCode: 0 });
      }
    );
  });
}
