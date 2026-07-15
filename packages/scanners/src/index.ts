/**
 * Passive security scanners — TLS, headers, DNS, and stack fingerprinting.
 *
 * Scanners that connect to the target directly (TLS, HTTP) must keep that connection behind
 * `validateScanTarget` (from `@janus/shared`) — never re-resolve a hostname independently.
 * That's what keeps scan targets safe from SSRF and DNS-rebinding attacks; see
 * packages/shared/src/scan-target. `scanTLS` takes an already-pinned address as input (the
 * caller must have validated first); `scanHeaders` and `fingerprintStack` call
 * `validateScanTarget` themselves, since redirect-following is inherently part of their job.
 * `scanDNS` is the exception: it only ever queries a trusted DNS resolver about the target
 * name — it never opens a connection to an address derived from it — so the SSRF class
 * `validateScanTarget` guards against doesn't apply there (see the comment in
 * dns/scan-dns.ts for the full reasoning).
 *
 * `fingerprintStack` cross-references detected software against `@janus/db`'s locally cached
 * CVE data (populated by the scheduled sync job in packages/workers) — it never queries NVD
 * live during a scan.
 *
 * `scoreReport` is the one module here that doesn't scan anything itself — it's a pure function
 * over the other four scanners' typed outputs, producing per-category letter grades and an
 * overall weighted score. See packages/scanners/src/report/score-report.ts for the weighting
 * rationale and the explicit non-compliance disclaimer it always returns.
 *
 * `domain-verification/` is a different kind of check: not a security scan, but the DNS-TXT /
 * well-known-file ownership challenge that gates the AUTHENTICATED scan tier on the `Domain`
 * Prisma model (see packages/db/src/domain-verification-repository.ts for persistence and
 * packages/workers/src/domain-verification-expiry for the scheduled 90-day expiry sweep). Its
 * well-known-file check goes through `validateScanTarget` like any other HTTP-connecting
 * scanner; its DNS TXT check doesn't, for the same reason `scanDNS` doesn't.
 */
export { scanTLS, type ScanTlsOptions } from './tls/scan-tls.js';
export { tlsScanResultSchema, type TlsScanResult } from './tls/types.js';
export type { TlsProtocolVersion } from './tls/connect.js';
export { scanHeaders, type ScanHeadersOptions } from './headers/scan-headers.js';
export { headersScanResultSchema, type HeadersScanResult } from './headers/types.js';
export {
  evaluateCookies,
  parseSetCookieHeader,
  type ParsedCookie,
} from './headers/cookie-flags.js';
export { scanDNS, type ScanDnsOptions } from './dns/scan-dns.js';
export { dnsScanResultSchema, type DnsScanResult } from './dns/types.js';
export { COMMON_DKIM_SELECTORS } from './dns/dkim.js';
export {
  queryRawDns,
  RawDnsQueryError,
  type RawDnsRecordType,
  type RawDnsErrorCode,
} from './dns/raw-dns-query.js';
export {
  lookupTxt,
  lookupMx,
  joinTxtRecord,
  type DnsLookupResult,
  type DnsLookupOptions,
} from './dns/dns-lookup.js';
export { fingerprintStack, type FingerprintStackOptions } from './fingerprint/scan-fingerprint.js';
export { fingerprintScanResultSchema, type FingerprintScanResult } from './fingerprint/types.js';
export {
  detectFromHeaders,
  type HeaderDetection,
  type HeaderInput,
} from './fingerprint/header-detectors.js';
export {
  evaluatePathCheck,
  PATH_CHECKS,
  GENERIC_TECH_PATH_CHECKS,
  type PathDetection,
  type PathCheckDefinition,
} from './fingerprint/path-detectors.js';
export { buildCveFindings } from './fingerprint/cve-matching.js';
export { scoreReport } from './report/score-report.js';
export { InsufficientScanDataError } from './report/errors.js';
export {
  CATEGORY_CONFIG,
  scoreToGrade,
  averageFindings,
  scorableFingerprintFindings,
  type CategoryConfig,
} from './report/grading.js';
export {
  reportCategorySchema,
  letterGradeSchema,
  categoryScoreSchema,
  scoreReportDisclaimerSchema,
  scoreReportSchema,
  type ScanResults,
  type ReportCategory,
  type LetterGrade,
  type CategoryScore,
  type ScoreReportDisclaimer,
  type ScoreReport,
} from './report/types.js';
export { generateVerificationToken } from './domain-verification/token.js';
export {
  VERIFICATION_TXT_RECORD_PREFIX,
  WELL_KNOWN_VERIFICATION_PATH,
  VERIFICATION_EXPIRY_DAYS,
  verificationTxtRecordName,
  buildVerificationInstructions,
  type VerificationInstructions,
} from './domain-verification/constants.js';
export {
  checkDnsTxtChallenge,
  type DnsChallengeOptions,
} from './domain-verification/dns-challenge.js';
export {
  checkWellKnownFileChallenge,
  type WellKnownChallengeOptions,
} from './domain-verification/well-known-challenge.js';
export {
  verifyDomainOwnership,
  type VerifyDomainOwnershipOptions,
} from './domain-verification/verify-domain-ownership.js';
