import { loadConfig } from '@janus/shared';
import * as Sentry from '@sentry/node';
import pino from 'pino';
import { createCveSyncQueue, createCveSyncWorker, scheduleCveSync } from './cve-sync/queue.js';
import {
  createDataRetentionQueue,
  createDataRetentionWorker,
  scheduleDataRetentionSweep,
} from './data-retention/queue.js';
import {
  createDomainVerificationExpiryQueue,
  createDomainVerificationExpiryWorker,
  scheduleDomainVerificationExpiryCheck,
} from './domain-verification-expiry/queue.js';
import { createScanWorker } from './scan-job/queue.js';
import { initSentry } from './sentry.js';

/**
 * Standalone entrypoint for every background job in this app — run this as its own long-lived
 * Node process (`node dist/main.js`, or as a Docker service), separate from the API process.
 *
 * Runs four things in one process: the always-on scan worker (the API enqueues a job via
 * `enqueueScanJob` and returns immediately; this is what actually pulls it off the queue), and
 * three scheduled sweeps (CVE sync, domain-verification expiry, data retention) registered as
 * BullMQ job schedulers on startup. Before Prompt 9, the latter two scheduled jobs were fully
 * built and tested (see cve-sync/ and domain-verification-expiry/) but never actually wired up
 * here — meaning verified domains never expired and the CVE cache never refreshed in any
 * running deployment. Fixed here alongside adding the new data-retention sweep, since this file
 * is exactly where that wiring belongs and leaving two of three near-identical scheduled jobs
 * silently disconnected while adding a third would be a worse state than either fixing all of
 * them or none.
 */
function main(): void {
  const config = loadConfig();
  const logger = pino({ name: 'worker', level: config.LOG_LEVEL });

  initSentry(config.SENTRY_DSN, config.NODE_ENV);

  const scanWorker = createScanWorker({ redisUrl: config.REDIS_URL });

  scanWorker.on('active', (job) => {
    logger.info({ jobId: job.id, targetUrl: job.data.targetUrl }, 'Scan job started');
  });
  scanWorker.on('completed', (job) => {
    logger.info(
      { jobId: job.id, targetUrl: job.data.targetUrl, result: job.returnvalue },
      'Scan job completed',
    );
  });
  scanWorker.on('failed', (job, err) => {
    logger.warn(
      { jobId: job?.id, targetUrl: job?.data.targetUrl, attemptsMade: job?.attemptsMade, err },
      'Scan job failed',
    );
    // Every attempt exhausted (job.attemptsMade === job's configured max) is the "unusual
    // failure rate" signal an operator actually wants paged on — a single retryable transient
    // failure isn't. Sentry can't distinguish that itself, so it's decided here.
    if (job !== undefined && job.attemptsMade >= (job.opts.attempts ?? 1)) {
      Sentry.captureException(err, {
        extra: { jobId: job.id, targetUrl: job.data.targetUrl, attemptsMade: job.attemptsMade },
      });
    }
  });
  scanWorker.on('error', (err) => {
    logger.error({ err }, 'Scan worker error');
    Sentry.captureException(err);
  });

  const nvdApiKey = process.env.NVD_API_KEY;
  const cveSyncQueue = createCveSyncQueue({ redisUrl: config.REDIS_URL });
  const cveSyncWorker = createCveSyncWorker({
    redisUrl: config.REDIS_URL,
    ...(nvdApiKey !== undefined ? { nvdApiKey } : {}),
  });
  cveSyncWorker.on('completed', (job) => {
    logger.info({ totalUpserted: job.returnvalue.totalUpserted }, 'CVE sync completed');
  });
  cveSyncWorker.on('failed', (job, err) => {
    logger.error({ err }, 'CVE sync failed');
    Sentry.captureException(err, { extra: { jobId: job?.id } });
  });

  const domainExpiryQueue = createDomainVerificationExpiryQueue({ redisUrl: config.REDIS_URL });
  const domainExpiryWorker = createDomainVerificationExpiryWorker({ redisUrl: config.REDIS_URL });
  domainExpiryWorker.on('completed', (job) => {
    logger.info(
      { expiredCount: job.returnvalue.expiredCount },
      'Domain verification expiry sweep completed',
    );
  });
  domainExpiryWorker.on('failed', (job, err) => {
    logger.error({ err }, 'Domain verification expiry sweep failed');
    Sentry.captureException(err, { extra: { jobId: job?.id } });
  });

  const dataRetentionQueue = createDataRetentionQueue({ redisUrl: config.REDIS_URL });
  const dataRetentionWorker = createDataRetentionWorker({
    redisUrl: config.REDIS_URL,
    retentionMonths: config.RETENTION_MONTHS,
  });
  dataRetentionWorker.on('completed', (job) => {
    // Record type + count only, never the deleted content itself — see Prompt 9's own
    // requirement, mirrored in the delete-account endpoint (packages/api/src/routes/legal.ts).
    logger.info(
      {
        cutoffDate: job.returnvalue.cutoffDate,
        scanReports: job.returnvalue.scanReports,
        scanConsents: job.returnvalue.scanConsents,
      },
      'Data retention sweep completed',
    );
  });
  dataRetentionWorker.on('failed', (job, err) => {
    logger.error({ err }, 'Data retention sweep failed');
    Sentry.captureException(err, { extra: { jobId: job?.id } });
  });

  void Promise.all([
    scheduleCveSync(cveSyncQueue, {
      redisUrl: config.REDIS_URL,
      ...(nvdApiKey !== undefined ? { nvdApiKey } : {}),
    }),
    scheduleDomainVerificationExpiryCheck(domainExpiryQueue),
    scheduleDataRetentionSweep(dataRetentionQueue),
  ]).catch((err: unknown) => {
    logger.error({ err }, 'Failed to register one or more scheduled job schedulers');
    Sentry.captureException(err);
  });

  let shuttingDown = false;
  function shutdown(signal: string): void {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'Shutting down workers');
    Promise.all([
      scanWorker.close(),
      cveSyncWorker.close(),
      domainExpiryWorker.close(),
      dataRetentionWorker.close(),
      cveSyncQueue.close(),
      domainExpiryQueue.close(),
      dataRetentionQueue.close(),
    ])
      .then(() => {
        process.exit(0);
      })
      .catch((err: unknown) => {
        logger.error({ err }, 'Error during worker shutdown');
        process.exit(1);
      });
  }
  process.on('SIGTERM', () => {
    shutdown('SIGTERM');
  });
  process.on('SIGINT', () => {
    shutdown('SIGINT');
  });

  logger.info({ concurrency: scanWorker.opts.concurrency }, 'Workers listening for jobs');
}

main();
