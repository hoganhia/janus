/**
 * Background job workers.
 *
 * `scan-job/` is the async scan pipeline: the API enqueues a job (`enqueueScanJob`) and returns
 * immediately; `createScanWorker`'s processor (`run-scan.ts`) re-validates the target via
 * `validateScanTarget` — never trusting the API layer's earlier check alone, since time has
 * passed since the job was enqueued, long enough for DNS to have been rebound — then runs every
 * Prompt-2 scanner concurrently, scores the result via `scoreReport`, and persists it via
 * `@janus/db`.
 *
 * `cve-sync/` is the one place NVD is ever queried, on a schedule, populating `@janus/db`'s
 * local cache that `fingerprintStack` reads from at scan time.
 *
 * `domain-verification-expiry/` runs daily, downgrading any domain whose successful ownership
 * verification (packages/scanners/src/domain-verification) has passed its 90-day expiry back to
 * the PASSIVE scan tier.
 *
 * `data-retention/` runs daily, deleting scan records and consent/IP-log records older than
 * RETENTION_MONTHS (see @janus/shared, default 12) — Prompt 9's data-retention requirement.
 */
export {
  createScanQueue,
  createScanWorker,
  enqueueScanJob,
  SCAN_JOB_ATTEMPTS,
  SCAN_JOB_BACKOFF_DELAY_MS,
  type ScanQueueOptions,
  type ScanWorkerOptions,
  type ScanQueueLike,
  type ScanJobLike,
} from './scan-job/queue.js';
export { runScanJob } from './scan-job/run-scan.js';
export type { ScanJobData, ScanJobResult } from './scan-job/types.js';
export {
  createCveSyncQueue,
  createCveSyncWorker,
  scheduleCveSync,
  type CveSyncJobData,
  type CveSyncJobResult,
  type CveSyncQueueOptions,
} from './cve-sync/queue.js';
export { syncAllProducts, type SyncAllOptions } from './cve-sync/sync-all.js';
export { syncProduct, type SyncProductResult } from './cve-sync/sync-product.js';
export {
  NvdClient,
  parseCpeCriteria,
  type NvdCveRecord,
  type NvdCveMetric,
} from './cve-sync/nvd-client.js';
export {
  createDomainVerificationExpiryQueue,
  createDomainVerificationExpiryWorker,
  scheduleDomainVerificationExpiryCheck,
  type DomainVerificationExpiryJobData,
  type DomainVerificationExpiryJobResult,
  type DomainVerificationExpiryQueueOptions,
} from './domain-verification-expiry/queue.js';
export {
  expireStaleDomainVerifications,
  type ExpireDomainVerificationsResult,
} from './domain-verification-expiry/expire-domains.js';
export {
  createDataRetentionQueue,
  createDataRetentionWorker,
  scheduleDataRetentionSweep,
  type DataRetentionJobData,
  type DataRetentionJobResult,
  type DataRetentionQueueOptions,
  type DataRetentionWorkerOptions,
} from './data-retention/queue.js';
export {
  runDataRetentionSweep,
  type RunDataRetentionSweepResult,
} from './data-retention/run-retention-sweep.js';
