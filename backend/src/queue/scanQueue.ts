import { Queue, Worker, Job } from "bullmq";
import Redis from "ioredis";
import ScanJob, { JobStatus } from "../models/ScanJob";
import { runScanPipeline } from "../services/scanOrchestratorService";

const QUEUE_NAME = "scan-pipeline";
const REDIS_HOST = process.env.REDIS_HOST || "localhost";
const REDIS_PORT = Number(process.env.REDIS_PORT) || 6379;

let redisConnection: Redis | null = null;
let scanQueue: Queue | null = null;
let scanWorker: Worker | null = null;
let isRedisAvailable = false;

function initRedis() {
  if (redisConnection) return;

  try {
    const redis = new Redis({
      host: REDIS_HOST,
      port: REDIS_PORT,
      maxRetriesPerRequest: null,
      enableOfflineQueue: false,
      lazyConnect: true,
      retryStrategy(times) {
        if (times > 2) {
          return null; // Stop retrying after 2 attempts
        }
        return Math.min(times * 200, 1000);
      }
    });

    redis.on("error", (err) => {
      if (isRedisAvailable) {
        console.warn(`[Queue] Redis connection lost: ${err.message}`);
      }
      isRedisAvailable = false;
    });

    redis.connect().then(() => {
      console.log(`[Queue] Connected to Redis at ${REDIS_HOST}:${REDIS_PORT}`);
      isRedisAvailable = true;
      redisConnection = redis;

      try {
        scanQueue = new Queue(QUEUE_NAME, { connection: redis });
        scanQueue.on("error", (err) => {
          console.warn(`[Queue] BullMQ Queue error: ${err.message}`);
        });

        scanWorker = new Worker(
          QUEUE_NAME,
          async (job: Job<{ scanId: string }>) => {
            await processQueueJob(job.data.scanId);
          },
          { connection: redis, concurrency: 3 }
        );

        scanWorker.on("error", (err) => {
          console.warn(`[Queue] BullMQ Worker error: ${err.message}`);
        });

        scanWorker.on("failed", (job, err) => {
          console.error(`[Worker] Job ${job?.id} failed for scan ${job?.data.scanId}:`, err.message);
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`[Queue] Failed to create BullMQ queue/worker: ${msg}`);
      }
    }).catch((err) => {
      console.warn(`[Queue] Redis not available at ${REDIS_HOST}:${REDIS_PORT} (${err.message}). In-memory execution enabled.`);
      isRedisAvailable = false;
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[Queue] Failed to initialize Redis queue: ${msg}. In-memory execution enabled.`);
    isRedisAvailable = false;
  }
}

// Initialize Redis queue on startup
initRedis();

export async function processQueueJob(scanId: string): Promise<void> {
  let scanJob = await ScanJob.findOne({ scanId });
  if (!scanJob) {
    scanJob = await ScanJob.create({
      scanId,
      status: "RUNNING",
      startedAt: new Date(),
      attemptCount: 1
    });
  } else {
    scanJob.status = "RUNNING";
    scanJob.startedAt = new Date();
    scanJob.attemptCount += 1;
    await scanJob.save();
  }

  try {
    await runScanPipeline(scanId);

    scanJob.status = "COMPLETED";
    scanJob.completedAt = new Date();
    await scanJob.save();
    console.log(`[Queue] ScanJob ${scanJob._id} for scan ${scanId} completed successfully.`);
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    scanJob.status = "FAILED";
    scanJob.completedAt = new Date();
    scanJob.error = errorMsg;
    await scanJob.save();
    console.error(`[Queue] ScanJob ${scanJob._id} for scan ${scanId} failed: ${errorMsg}`);
    throw err;
  }
}

/**
 * Enqueue a scan job for async background processing.
 */
export async function enqueueScanJob(scanId: string): Promise<{ jobStatus: JobStatus; jobId?: string }> {
  const scanJob = await ScanJob.create({
    scanId,
    status: "QUEUED",
    attemptCount: 0
  });

  if (isRedisAvailable && scanQueue) {
    try {
      const job = await scanQueue.add("run-scan", { scanId }, {
        attempts: 3,
        backoff: { type: "exponential", delay: 2000 }
      });
      console.log(`[Queue] Scan ${scanId} enqueued in Redis Queue (Job ID: ${job.id})`);
      return { jobStatus: "QUEUED", jobId: job.id };
    } catch (err) {
      console.warn("[Queue] Failed to push job to BullMQ, falling back to in-memory execution:", err);
    }
  }

  // Fallback to in-memory async processing
  console.log(`[Queue] Processing scan ${scanId} via in-memory queue fallback.`);
  processQueueJob(scanId).catch((err) => {
    console.error(`[Queue] In-memory job execution failed for scan ${scanId}:`, err);
  });

  return { jobStatus: "QUEUED", jobId: String(scanJob._id) };
}
