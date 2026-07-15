import { loadConfig } from '@janus/shared';
import pino from 'pino';
import { createScanWorker } from './scan-job/queue.js';

/**
 * Standalone entrypoint for the scan worker process — run this as its own long-lived Node
 * process (`node dist/main.js`, or as a Docker service), separate from the API process. The API
 * only ever enqueues jobs (see packages/api/src/routes/scans.ts); this is what actually pulls
 * them off the queue and runs the scanners.
 */
function main(): void {
  const config = loadConfig();
  const logger = pino({ name: 'scan-worker', level: config.LOG_LEVEL });

  const worker = createScanWorker({ redisUrl: config.REDIS_URL });

  worker.on('active', (job) => {
    logger.info({ jobId: job.id, targetUrl: job.data.targetUrl }, 'Scan job started');
  });
  worker.on('completed', (job) => {
    logger.info(
      { jobId: job.id, targetUrl: job.data.targetUrl, result: job.returnvalue },
      'Scan job completed',
    );
  });
  worker.on('failed', (job, err) => {
    logger.warn(
      { jobId: job?.id, targetUrl: job?.data.targetUrl, attemptsMade: job?.attemptsMade, err },
      'Scan job failed',
    );
  });
  worker.on('error', (err) => {
    logger.error({ err }, 'Scan worker error');
  });

  let shuttingDown = false;
  function shutdown(signal: string): void {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'Shutting down scan worker');
    worker
      .close()
      .then(() => {
        process.exit(0);
      })
      .catch((err: unknown) => {
        logger.error({ err }, 'Error during scan worker shutdown');
        process.exit(1);
      });
  }
  process.on('SIGTERM', () => {
    shutdown('SIGTERM');
  });
  process.on('SIGINT', () => {
    shutdown('SIGINT');
  });

  logger.info({ concurrency: worker.opts.concurrency }, 'Scan worker listening for jobs');
}

main();
