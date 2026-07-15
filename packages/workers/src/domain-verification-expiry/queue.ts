import { Queue, Worker, type ConnectionOptions } from 'bullmq';
import {
  expireStaleDomainVerifications,
  type ExpireDomainVerificationsResult,
} from './expire-domains.js';

const QUEUE_NAME = 'domain-verification-expiry';
const JOB_SCHEDULER_ID = 'expire-domain-verifications';
/** Once a day, at 3am — expiry is a 90-day-scale concern, no need for tighter polling. */
const DEFAULT_CRON_PATTERN = '0 3 * * *';

/** No per-run parameters — every run just checks "what's expired as of now." */
export type DomainVerificationExpiryJobData = Record<string, never>;
export type DomainVerificationExpiryJobResult = ExpireDomainVerificationsResult;

export interface DomainVerificationExpiryQueueOptions {
  redisUrl: string;
  cronPattern?: string;
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

export function createDomainVerificationExpiryQueue(
  options: DomainVerificationExpiryQueueOptions,
): Queue<DomainVerificationExpiryJobData, DomainVerificationExpiryJobResult> {
  return new Queue(QUEUE_NAME, { connection: createConnectionOptions(options.redisUrl) });
}

/** Registers (or updates) the repeatable schedule. Idempotent — safe to call on every worker
 * process startup. */
export async function scheduleDomainVerificationExpiryCheck(
  queue: Queue<DomainVerificationExpiryJobData, DomainVerificationExpiryJobResult>,
  options: Pick<DomainVerificationExpiryQueueOptions, 'cronPattern'> = {},
): Promise<void> {
  await queue.upsertJobScheduler(
    JOB_SCHEDULER_ID,
    { pattern: options.cronPattern ?? DEFAULT_CRON_PATTERN },
    { data: {} },
  );
}

/**
 * Processes the scheduled expiry sweep — see expire-domains.ts for the actual downgrade logic.
 */
export function createDomainVerificationExpiryWorker(
  options: DomainVerificationExpiryQueueOptions,
): Worker<DomainVerificationExpiryJobData, DomainVerificationExpiryJobResult> {
  return new Worker<DomainVerificationExpiryJobData, DomainVerificationExpiryJobResult>(
    QUEUE_NAME,
    async () => expireStaleDomainVerifications(),
    { connection: createConnectionOptions(options.redisUrl) },
  );
}
