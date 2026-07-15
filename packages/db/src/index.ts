export { getPrismaClient } from './client.js';
export {
  findCvesForProduct,
  upsertCve,
  recordSyncResult,
  type MatchedCve,
  type CveUpsertInput,
  type CveAffectedRangeInput,
} from './cve-repository.js';
export { compareVersions, isVersionInRange, type VersionRange } from './version-compare.js';
export { PRODUCT_CATALOG, findProductByKey, type ProductCatalogEntry } from './product-catalog.js';
export {
  findOrCreateDomain,
  recordScanReport,
  getScanReportHistory,
  getScanReportById,
  type RecordScanReportInput,
  type ScanReportHistoryOptions,
  type ScanReportWithDomain,
} from './scan-report-repository.js';
export {
  findDomainByName,
  startDomainVerification,
  markDomainVerified,
  markDomainVerificationFailed,
  findExpiredVerifications,
  downgradeExpiredVerification,
  type MarkDomainVerifiedInput,
} from './domain-verification-repository.js';
export type {
  Severity,
  LetterGrade,
  DomainVerificationStatus,
  DomainVerificationMethod,
  ScanTier,
  Domain,
  ScanReport,
  PrismaClient,
  Prisma,
} from './generated/prisma/client.js';
