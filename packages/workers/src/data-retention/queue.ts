import { Queue, Worker, type ConnectionOptions } from 'bullmq';
import { runDataRetentionSweep, type RunDataRetentionSweepResult } from './run-retention-sweep.js';

const QUEUE_NAME = 'data-retention';
const JOB_SCHEDULER_ID = 'run-data-retention-sweep';
/** Once a day, at 4am — a day's slop on a months-scale retention window is irrelevant, and
 * this keeps it off the 3am domain-verification-expiry slot. */
const DEFAULT_CRON_PATTERN = '0 4 * * *';

/** No per-run parameters — `retentionMonths` is fixed at worker-creation time (from config),
 * not per-job; every run just checks "what's older than the cutoff as of now." */
export type DataRetentionJobData = Record<string, never>;
export type DataRetentionJobResult = RunDataRetentionSweepResult;

export interface DataRetentionQueueOptions {
  redisUrl: string;
  cronPattern?: string;
}

export interface DataRetentionWorkerOptions extends DataRetentionQueueOptions {
  /** Months of history to keep before a record is deleted — see RETENTION_MONTHS in
   * @janus/shared. Default: 12. */
  retentionMonths?: number;
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

export function createDataRetentionQueue(
  options: DataRetentionQueueOptions,
): Queue<DataRetentionJobData, DataRetentionJobResult> {
  return new Queue(QUEUE_NAME, { connection: createConnectionOptions(options.redisUrl) });
}

/** Registers (or updates) the repeatable schedule. Idempotent — safe to call on every worker
 * process startup. */
export async function scheduleDataRetentionSweep(
  queue: Queue<DataRetentionJobData, DataRetentionJobResult>,
  options: Pick<DataRetentionQueueOptions, 'cronPattern'> = {},
): Promise<void> {
  await queue.upsertJobScheduler(
    JOB_SCHEDULER_ID,
    { pattern: options.cronPattern ?? DEFAULT_CRON_PATTERN },
    { data: {} },
  );
}

const DEFAULT_RETENTION_MONTHS = 12;

/**
 * Processes the scheduled retention sweep — see run-retention-sweep.ts for the actual deletion
 * logic.
 */
export function createDataRetentionWorker(
  options: DataRetentionWorkerOptions,
): Worker<DataRetentionJobData, DataRetentionJobResult> {
  return new Worker<DataRetentionJobData, DataRetentionJobResult>(
    QUEUE_NAME,
    async () => runDataRetentionSweep(options.retentionMonths ?? DEFAULT_RETENTION_MONTHS),
    { connection: createConnectionOptions(options.redisUrl) },
  );
}
