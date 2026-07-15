import { findDomainByName, recordScanReport, type Prisma } from '@janus/db';
import {
  fingerprintStack,
  scanDNS,
  scanHeaders,
  scanTLS,
  scoreReport,
  type DnsScanResult,
  type FingerprintScanResult,
  type HeadersScanResult,
  type ScanResults,
  type TlsScanResult,
} from '@janus/scanners';
import {
  ScanTargetRejectedError,
  validateScanTarget,
  type ScanFinding,
  type ScanTargetRejectionReason,
} from '@janus/shared';
import { UnrecoverableError } from 'bullmq';
import type { ScanJobData, ScanJobResult } from './types.js';

const DEFAULT_PORT = 443;

// Passed as each scanner's own internal per-request timeout option, so the *normal* failure
// path (target slow/unreachable) produces that scanner's own well-worded connection-failure
// finding rather than falling through to the generic timeoutFinding() below.
const SCANNER_INNER_TIMEOUT_MS = 8000;

// Outer hard backstops raced via withTimeout() against each scanner call. These should not
// normally fire — every scanner already claims to never throw and to respect its own inner
// timeout above — they exist only as a last-resort guard against a genuine hang (a bug, or a
// pathological target) so one stuck scanner can never keep the whole job (and therefore the
// worker's concurrency slot) occupied forever. Sized generously above the inner timeout to
// leave room for the scanner's own graceful handling to win first.
const TLS_OUTER_TIMEOUT_MS = SCANNER_INNER_TIMEOUT_MS + 4000;
const HEADERS_OUTER_TIMEOUT_MS = SCANNER_INNER_TIMEOUT_MS * 2 + 6000; // validateScanTarget's own redirect chase, then one GET
const FINGERPRINT_OUTER_TIMEOUT_MS = SCANNER_INNER_TIMEOUT_MS * 3 + 8000; // main page + several sequential path checks
// scanDNS has no overridable timeout of its own (see packages/scanners/src/dns/scan-dns.ts) —
// this outer budget is the *only* time bound available at this layer. Sized to comfortably
// cover its worst case: DNSSEC evaluation can chain two sequential 5s raw queries internally.
const DNS_OUTER_TIMEOUT_MS = 20_000;

/**
 * Reasons `validateScanTarget` can reject a target for which retrying with the exact same URL
 * would fail identically every time — a deterministic policy/shape rejection, not a transient
 * network condition. `PROBE_FAILED` is deliberately excluded: it means the validation probe
 * itself failed (e.g. the target was briefly unreachable), which is exactly the kind of
 * transient condition BullMQ's `attempts`/`backoff` retry is for.
 */
const UNRECOVERABLE_REJECTION_REASONS: ReadonlySet<ScanTargetRejectionReason> = new Set([
  'MALFORMED_URL',
  'UNSUPPORTED_PROTOCOL',
  'CREDENTIALS_IN_URL',
  'BLOCKED_HOSTNAME',
  'DENIED_BY_LIST',
  'NOT_ALLOWLISTED',
  'PRIVATE_ADDRESS',
  'TOO_MANY_REDIRECTS',
  'OPTED_OUT',
]);

class ScannerTimeoutError extends Error {}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new ScannerTimeoutError(`${label} scan exceeded its ${String(timeoutMs)}ms budget`));
    }, timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

function timeoutFinding(id: string, label: string, timeoutMs: number): ScanFinding {
  return {
    id,
    label,
    status: 'fail',
    explanation: `This check did not finish within ${String(Math.round(timeoutMs / 1000))}s and was abandoned so the rest of the scan could complete. The target may be slow, unreachable, or blocking automated requests.`,
  };
}

function describeReason(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}

function fallbackTlsResult(hostname: string, scannedAt: string, reason: unknown): TlsScanResult {
  return {
    hostname,
    port: DEFAULT_PORT,
    scannedAt,
    findings: [
      {
        ...timeoutFinding('tls.connection', 'TLS connection', TLS_OUTER_TIMEOUT_MS),
        details: { error: describeReason(reason) },
      },
    ],
  };
}

function fallbackHeadersResult(url: string, scannedAt: string, reason: unknown): HeadersScanResult {
  return {
    url,
    scannedAt,
    findings: [
      {
        ...timeoutFinding('headers.connection', 'HTTP connection', HEADERS_OUTER_TIMEOUT_MS),
        details: { error: describeReason(reason) },
      },
    ],
  };
}

function fallbackDnsResult(domain: string, scannedAt: string, reason: unknown): DnsScanResult {
  return {
    domain,
    scannedAt,
    findings: [
      {
        ...timeoutFinding('dns.timeout', 'DNS lookups', DNS_OUTER_TIMEOUT_MS),
        details: { error: describeReason(reason) },
      },
    ],
  };
}

function fallbackFingerprintResult(
  url: string,
  scannedAt: string,
  reason: unknown,
): FingerprintScanResult {
  return {
    url,
    scannedAt,
    caveat:
      'This scan did not complete in time, so no software or version detection was attempted.',
    findings: [
      {
        ...timeoutFinding(
          'fingerprint.connection',
          'HTTP connection',
          FINGERPRINT_OUTER_TIMEOUT_MS,
        ),
        details: { error: describeReason(reason) },
      },
    ],
  };
}

function runTlsScan(hostname: string, pinnedAddress: string): Promise<TlsScanResult> {
  return withTimeout(
    scanTLS(hostname, pinnedAddress, { timeoutMs: SCANNER_INNER_TIMEOUT_MS }),
    TLS_OUTER_TIMEOUT_MS,
    'tls',
  );
}

function runHeadersScan(url: string, data: ScanJobData): Promise<HeadersScanResult> {
  return withTimeout(
    scanHeaders(url, {
      requesterIp: data.requesterIp,
      userAgent: data.userAgent,
      headersTimeoutMs: SCANNER_INNER_TIMEOUT_MS,
      bodyTimeoutMs: SCANNER_INNER_TIMEOUT_MS,
    }),
    HEADERS_OUTER_TIMEOUT_MS,
    'headers',
  );
}

function runDnsScan(domain: string): Promise<DnsScanResult> {
  return withTimeout(scanDNS(domain), DNS_OUTER_TIMEOUT_MS, 'dns');
}

function runFingerprintScan(url: string, data: ScanJobData): Promise<FingerprintScanResult> {
  return withTimeout(
    fingerprintStack(url, {
      requesterIp: data.requesterIp,
      userAgent: data.userAgent,
      headersTimeoutMs: SCANNER_INNER_TIMEOUT_MS,
      bodyTimeoutMs: SCANNER_INNER_TIMEOUT_MS,
    }),
    FINGERPRINT_OUTER_TIMEOUT_MS,
    'fingerprint',
  );
}

/**
 * Runs one scan job end to end: re-validates the target (never trusting the API layer's
 * earlier check alone — time has passed since the job was enqueued, long enough for DNS to
 * have been rebound), runs all four scanners concurrently via `Promise.allSettled` so one
 * hanging/failing scanner can't block or drop the others, scores the aggregate via
 * `scoreReport`, and persists both the raw results and the computed score via
 * `recordScanReport`.
 *
 * Throws `UnrecoverableError` for a deterministic target rejection (private address, blocked
 * hostname, malformed URL, etc.) so BullMQ doesn't burn its retry budget re-running a scan that
 * will fail identically every time; any other error (a transient validation-probe failure, a
 * database hiccup while recording the report) propagates normally so the queue's
 * `attempts`/`backoff` retry policy applies.
 */
export async function runScanJob(data: ScanJobData): Promise<ScanJobResult> {
  // Re-checked here (not just trusted from the API layer's own lookup at submission time) for
  // the same reason the target itself is re-validated below: enough time may have passed since
  // enqueue for the domain's verification status — or the opt-out record itself — to have
  // changed. A malformed target URL is left for validateScanTarget below to reject with its
  // usual clear MALFORMED_URL reason rather than duplicating that check here.
  let skipOptOutCheck = false;
  try {
    const domainRow = await findDomainByName(new URL(data.targetUrl).hostname);
    skipOptOutCheck = domainRow?.scanTier === 'AUTHENTICATED';
  } catch {
    // Malformed URL — fall through to validateScanTarget's own rejection below.
  }

  let validated;
  try {
    validated = await validateScanTarget(data.targetUrl, {
      requesterIp: data.requesterIp,
      userAgent: data.userAgent,
      skipOptOutCheck,
    });
  } catch (err) {
    if (err instanceof ScanTargetRejectedError && UNRECOVERABLE_REJECTION_REASONS.has(err.reason)) {
      throw new UnrecoverableError(`Scan target rejected (${err.reason}): ${err.message}`);
    }
    throw err;
  }

  const finalUrl = new URL(validated.finalUrl);
  const domain = finalUrl.hostname;
  const scannedAt = new Date().toISOString();

  // Every scanner here targets the same already-resolved `validated.finalUrl` (not the
  // original, possibly-redirecting `data.targetUrl`) so the four results describe one
  // consistent destination rather than each independently re-walking (and potentially
  // resolving to a different final hop of) the same redirect chain.
  const [tlsSettled, headersSettled, dnsSettled, fingerprintSettled] = await Promise.allSettled([
    runTlsScan(finalUrl.hostname, validated.pinnedAddress),
    runHeadersScan(validated.finalUrl, data),
    runDnsScan(domain),
    runFingerprintScan(validated.finalUrl, data),
  ]);

  const scanResults: ScanResults = {
    tls:
      tlsSettled.status === 'fulfilled'
        ? tlsSettled.value
        : fallbackTlsResult(finalUrl.hostname, scannedAt, tlsSettled.reason),
    headers:
      headersSettled.status === 'fulfilled'
        ? headersSettled.value
        : fallbackHeadersResult(validated.finalUrl, scannedAt, headersSettled.reason),
    dns:
      dnsSettled.status === 'fulfilled'
        ? dnsSettled.value
        : fallbackDnsResult(domain, scannedAt, dnsSettled.reason),
    fingerprint:
      fingerprintSettled.status === 'fulfilled'
        ? fingerprintSettled.value
        : fallbackFingerprintResult(validated.finalUrl, scannedAt, fingerprintSettled.reason),
  };

  const report = scoreReport(scanResults, scannedAt);

  // ScanFinding.details is typed as Record<string, unknown> (deliberately, since findings carry
  // heterogeneous scanner-specific payloads) — that `unknown` doesn't structurally satisfy
  // Prisma's recursive InputJsonValue type even though everything in it is plain
  // JSON-serializable data at runtime, hence the cast. `report` (ScoreReport) needs no such
  // cast — every field in it is already a plain JSON-compatible type.
  const savedReport = await recordScanReport({
    domain,
    scannedAt: new Date(scannedAt),
    rawResults: scanResults as unknown as Prisma.InputJsonValue,
    computedScore: report,
    overallGrade: report.overallGrade,
    overallScore: report.overallScore,
  });

  return {
    domain,
    scanReportId: savedReport.id,
    overallScore: report.overallScore,
    overallGrade: report.overallGrade,
  };
}
