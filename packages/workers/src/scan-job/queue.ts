import { randomUUID } from 'node:crypto';
import {
  Queue,
  Worker,
  type ConnectionOptions,
  type Job,
  type JobsOptions,
  type JobState,
} from 'bullmq';
import { runScanJob } from './run-scan.js';
import type { ScanJobData, ScanJobResult } from './types.js';

const QUEUE_NAME = 'scan';
const JOB_NAME = 'run-scan';

/** Hard cap on retry attempts ("so a broken target doesn't loop forever") — a target that's
 * genuinely broken fails identically every attempt; this just bounds the wasted work/delay
 * before giving up. See run-scan.ts for how deterministic target rejections skip retries
 * entirely via UnrecoverableError instead of burning this budget. */
export const SCAN_JOB_ATTEMPTS = 3;
export const SCAN_JOB_BACKOFF_DELAY_MS = 5000;

const DEFAULT_WORKER_CONCURRENCY = 5;
const DEFAULT_WORKER_RATE_LIMIT_MAX = 30;
const DEFAULT_WORKER_RATE_LIMIT_DURATION_MS = 60_000;

export interface ScanQueueOptions {
  redisUrl: string;
}

export interface ScanWorkerOptions extends ScanQueueOptions {
  /**
   * Max scan jobs this worker instance processes concurrently — bounds how much outbound
   * scanning traffic (and load on our own DNS/TLS/HTTP stack) it generates at once, independent
   * of how many jobs are queued. Default: 5.
   */
  concurrency?: number;
  /**
   * Global throughput cap (jobs *started* per `rateLimitDurationMs`), across every IP and every
   * target combined — not a per-IP limit. BullMQ's open-source rate limiter (`Worker`'s
   * `limiter` option) has no per-key/per-group scoping; grouped/per-identity rate limiting is a
   * BullMQ Pro feature, not available in the `bullmq` package used here. The actual "max N
   * scans per IP per hour" policy is enforced per-request at the API layer instead
   * (`@fastify/rate-limit`, see packages/api/src/routes/scans.ts) — which is also the more
   * useful place for it: it rejects an over-quota request with an immediate 429 before it's
   * ever enqueued, rather than silently queueing work that would just sit rate-limited here.
   * This worker-level limiter is a second, independent line of defense: even a flood of
   * requests spread across many different IPs (each individually within its own per-IP quota)
   * still can't make this worker fire off an unbounded burst of outbound scans. Default: 30
   * jobs / 60s.
   */
  rateLimitMax?: number;
  rateLimitDurationMs?: number;
}

/**
 * Passed as a plain options object (not a constructed ioredis client) — see
 * cve-sync/queue.ts's identical helper for why constructing our own `Redis` instance causes a
 * duplicate-package-version type conflict with BullMQ's bundled ioredis.
 */
function createConnectionOptions(redisUrl: string): ConnectionOptions {
  const url = new URL(redisUrl);
  return {
    host: url.hostname,
    port: url.port !== '' ? Number(url.port) : 6379,
    ...(url.password !== '' ? { password: url.password } : {}),
    maxRetriesPerRequest: null,
  };
}

/**
 * The subset of a scan `Job` that route handlers (`GET /scans/:jobId/status`) actually need —
 * deliberately narrower than BullMQ's full `Job` class so a test double can satisfy it with a
 * plain object, without needing to fake every method a real `Job` instance carries.
 */
export interface ScanJobLike {
  id?: string;
  data: ScanJobData;
  getState(): Promise<JobState | 'unknown'>;
  returnvalue: ScanJobResult;
  failedReason: string;
}

/**
 * The subset of a scan `Queue` that route handlers actually need — see `ScanJobLike` for why
 * this is narrower than BullMQ's full `Queue` class. A real `Queue<ScanJobData, ScanJobResult>`
 * instance (from `createScanQueue`) satisfies this structurally; so does a plain test double.
 */
export interface ScanQueueLike {
  add(name: string, data: ScanJobData, opts: JobsOptions): Promise<Job<ScanJobData, ScanJobResult>>;
  getJob(jobId: string): Promise<ScanJobLike | undefined>;
}

export function createScanQueue(options: ScanQueueOptions): Queue<ScanJobData, ScanJobResult> {
  return new Queue(QUEUE_NAME, { connection: createConnectionOptions(options.redisUrl) });
}

/**
 * Enqueues one scan job with a random (non-sequential) job ID — BullMQ's default auto-increment
 * IDs would make `GET /scans/:jobId/status` results (which include the full report once
 * complete) trivially enumerable by anyone who can count. Retries up to `SCAN_JOB_ATTEMPTS`
 * times with exponential backoff for transient failures. Completed/failed job records are kept
 * for a bounded window so status polling keeps working after a job finishes, without Redis
 * holding scan history forever.
 */
export async function enqueueScanJob(
  queue: ScanQueueLike,
  data: ScanJobData,
): Promise<Job<ScanJobData, ScanJobResult>> {
  return queue.add(JOB_NAME, data, {
    jobId: randomUUID(),
    attempts: SCAN_JOB_ATTEMPTS,
    backoff: { type: 'exponential', delay: SCAN_JOB_BACKOFF_DELAY_MS },
    removeOnComplete: { age: 24 * 60 * 60 },
    removeOnFail: { age: 7 * 24 * 60 * 60 },
  });
}

/**
 * Processes scan jobs: re-validates the target, runs every Prompt-2 scanner concurrently, scores
 * and persists the result (see run-scan.ts). `concurrency` bounds how much simultaneous outbound
 * scanning this worker generates; `limiter` is a global (not per-IP — see
 * `ScanWorkerOptions.rateLimitMax`) throughput cap, a second line of defense on top of the API
 * layer's per-IP submission limit.
 */
export function createScanWorker(options: ScanWorkerOptions): Worker<ScanJobData, ScanJobResult> {
  return new Worker<ScanJobData, ScanJobResult>(
    QUEUE_NAME,
    (job: Job<ScanJobData>) => runScanJob(job.data),
    {
      connection: createConnectionOptions(options.redisUrl),
      concurrency: options.concurrency ?? DEFAULT_WORKER_CONCURRENCY,
      limiter: {
        max: options.rateLimitMax ?? DEFAULT_WORKER_RATE_LIMIT_MAX,
        duration: options.rateLimitDurationMs ?? DEFAULT_WORKER_RATE_LIMIT_DURATION_MS,
      },
    },
  );
}
