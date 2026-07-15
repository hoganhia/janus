import pino, { type Logger } from 'pino';
import { resolvePublicAddress, UnsafeScanTargetError } from '../net/ssrf-guard.js';
import { checkOptOut } from './check-opt-out.js';
import { ScanTargetRejectedError, type ScanTargetRejectionReason } from './errors.js';
import { probePinned } from './pinned-request.js';
import type { ScanTargetListStore } from './scan-target-list-store.js';

const BLOCKED_HOSTNAME_SUFFIXES = ['.local', '.internal'];

const defaultLogger = pino({ name: 'scan-target-validator' });

export interface ValidateScanTargetOptions {
  requesterIp: string;
  listStore?: ScanTargetListStore;
  logger?: Logger;
  /** Default: 5. */
  maxRedirects?: number;
  /** Sent on every probe request made while resolving redirects, so scanned sites can identify our traffic. */
  userAgent?: string;
  /**
   * Skips the `_janus-opt-out.<hostname>` DNS TXT check (see check-opt-out.ts) — set this
   * when the caller has already confirmed the target domain's owner initiated (or otherwise
   * consented to) this specific scan, e.g. a domain with `scanTier === 'AUTHENTICATED'` via the
   * ownership verification flow. Default: false (the opt-out record is honored).
   */
  skipOptOutCheck?: boolean;
}

export interface ValidatedScanTarget {
  requestedUrl: string;
  finalUrl: string;
  pinnedAddress: string;
  family: 4 | 6;
  redirectCount: number;
}

function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return host === 'localhost' || BLOCKED_HOSTNAME_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

interface ValidatedHop {
  url: URL;
  address: string;
  family: 4 | 6;
}

async function validateHop(
  urlString: string,
  listStore: ScanTargetListStore | undefined,
  skipOptOutCheck: boolean,
): Promise<ValidatedHop> {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    throw new ScanTargetRejectedError('MALFORMED_URL', 'Target must be a valid URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ScanTargetRejectedError(
      'UNSUPPORTED_PROTOCOL',
      'Only http and https URLs are allowed',
    );
  }
  if (url.username || url.password) {
    throw new ScanTargetRejectedError('CREDENTIALS_IN_URL', 'URLs must not contain credentials');
  }
  if (isBlockedHostname(url.hostname)) {
    throw new ScanTargetRejectedError('BLOCKED_HOSTNAME', 'Target hostname is not scannable');
  }

  if (listStore) {
    if (await listStore.isDenied(url.hostname)) {
      throw new ScanTargetRejectedError('DENIED_BY_LIST', 'Target is on the deny list');
    }
    if (!(await listStore.isAllowed(url.hostname))) {
      throw new ScanTargetRejectedError('NOT_ALLOWLISTED', 'Target is not on the allow list');
    }
  }

  if (!skipOptOutCheck && (await checkOptOut(url.hostname))) {
    throw new ScanTargetRejectedError(
      'OPTED_OUT',
      'Target has opted out of scanning via DNS TXT record',
    );
  }

  try {
    const { address, family } = await resolvePublicAddress(url.hostname);
    return { url, address, family };
  } catch (err) {
    if (err instanceof UnsafeScanTargetError) {
      throw new ScanTargetRejectedError(
        'PRIVATE_ADDRESS',
        'Target must resolve to a public address',
      );
    }
    throw err;
  }
}

/**
 * The single gate every scanner must pass a target through before connecting to it. Validates
 * URL shape, blocked hostnames, the allow/deny list, the `_janus-opt-out` DNS TXT record
 * (see check-opt-out.ts), and that the target resolves to a public address — then makes a real
 * (redirect-disabled) probe request over a socket pinned to that validated address, following
 * any redirect chain manually and re-running every check (including the opt-out record) against
 * each hop's target before following it. Every attempt, successful or not, is logged for abuse
 * monitoring.
 */
export async function validateScanTarget(
  rawUrl: string,
  options: ValidateScanTargetOptions,
): Promise<ValidatedScanTarget> {
  const logger = options.logger ?? defaultLogger;
  const maxRedirects = options.maxRedirects ?? 5;
  const timestamp = new Date().toISOString();

  let currentUrlString = rawUrl;
  let redirectCount = 0;

  try {
    for (;;) {
      const { url, address, family } = await validateHop(
        currentUrlString,
        options.listStore,
        options.skipOptOutCheck ?? false,
      );

      const probe = await probePinned(
        url,
        address,
        options.userAgent !== undefined ? { userAgent: options.userAgent } : {},
      );
      const isRedirect =
        probe.statusCode >= 300 && probe.statusCode < 400 && probe.location !== undefined;
      if (isRedirect) {
        if (redirectCount >= maxRedirects) {
          throw new ScanTargetRejectedError(
            'TOO_MANY_REDIRECTS',
            `Exceeded ${String(maxRedirects)} redirects`,
          );
        }
        redirectCount += 1;
        currentUrlString = new URL(probe.location as string, url).toString();
        continue;
      }

      const result: ValidatedScanTarget = {
        requestedUrl: rawUrl,
        finalUrl: url.toString(),
        pinnedAddress: address,
        family,
        redirectCount,
      };
      logger.info(
        {
          requesterIp: options.requesterIp,
          targetUrl: rawUrl,
          finalUrl: result.finalUrl,
          redirectCount,
          timestamp,
        },
        'Scan target validated',
      );
      return result;
    }
  } catch (err) {
    const reason: ScanTargetRejectionReason =
      err instanceof ScanTargetRejectedError ? err.reason : 'PROBE_FAILED';
    logger.warn(
      { requesterIp: options.requesterIp, targetUrl: rawUrl, reason, redirectCount, timestamp },
      'Scan target rejected',
    );
    if (err instanceof ScanTargetRejectedError) throw err;
    throw new ScanTargetRejectedError('PROBE_FAILED', 'Failed to validate target');
  }
}
