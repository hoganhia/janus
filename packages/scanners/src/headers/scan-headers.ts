import {
  fetchPinned,
  ScanTargetRejectedError,
  validateScanTarget,
  type ScanFinding,
  type ScanTargetListStore,
} from '@janus/shared';
import { evaluateCookies } from './cookie-flags.js';
import { evaluateSecurityHeaders } from './security-headers.js';
import type { HeadersScanResult } from './types.js';

export interface ScanHeadersOptions {
  requesterIp: string;
  /**
   * Identifies this request as an automated security scan, e.g.
   * `"JanusSecurityScanner/1.0 (+https://example.com/about-scans)"`. Required, with no
   * built-in default — a placeholder domain would be actively misleading if it ever shipped
   * un-customized. The linked page should explain what the scan is and how to opt out.
   */
  userAgent: string;
  listStore?: ScanTargetListStore;
  /** Default: 3. */
  maxRedirects?: number;
  /** Default: 5000. */
  headersTimeoutMs?: number;
  /** Default: 5000. */
  bodyTimeoutMs?: number;
  /** Default: 2 MiB. */
  maxBodyBytes?: number;
}

const DEFAULT_MAX_REDIRECTS = 3;
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;

function headerString(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function connectionFailureResult(url: string, scannedAt: string, err: unknown): HeadersScanResult {
  const reason = err instanceof ScanTargetRejectedError ? err.reason : undefined;
  return {
    url,
    scannedAt,
    findings: [
      {
        id: 'headers.connection',
        label: 'HTTP connection',
        status: 'fail',
        explanation:
          reason !== undefined
            ? `Could not fetch headers from ${url}: the target failed validation (${reason}).`
            : `Could not fetch headers from ${url}. The site may be down, blocking scans, or unreachable.`,
        details: { error: err instanceof Error ? err.message : String(err) },
      },
    ],
  };
}

/**
 * Scans a target's HTTP response headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
 * Referrer-Policy, Permissions-Policy, and Set-Cookie flags. Redirects (up to `maxRedirects`)
 * are resolved and re-validated entirely by `validateScanTarget` — every hop it follows is
 * independently checked against the SSRF/rebinding guards, so this function never connects
 * anywhere `validateScanTarget` hasn't already approved. Exactly one GET request is then made,
 * against the final validated target, to read the headers actually being evaluated. A scan
 * failure is always returned as a `fail` finding, never thrown.
 */
export async function scanHeaders(
  url: string,
  options: ScanHeadersOptions,
): Promise<HeadersScanResult> {
  const scannedAt = new Date().toISOString();

  try {
    const validated = await validateScanTarget(url, {
      requesterIp: options.requesterIp,
      maxRedirects: options.maxRedirects ?? DEFAULT_MAX_REDIRECTS,
      userAgent: options.userAgent,
      ...(options.listStore !== undefined ? { listStore: options.listStore } : {}),
    });

    const finalUrl = new URL(validated.finalUrl);
    const response = await fetchPinned(finalUrl, validated.pinnedAddress, {
      userAgent: options.userAgent,
      headersTimeoutMs: options.headersTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      bodyTimeoutMs: options.bodyTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxBodyBytes: options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
    });

    const isHttps = finalUrl.protocol === 'https:';
    const findings: ScanFinding[] = [
      ...evaluateSecurityHeaders({
        csp: headerString(response.headers['content-security-policy']),
        hsts: headerString(response.headers['strict-transport-security']),
        xFrameOptions: headerString(response.headers['x-frame-options']),
        xContentTypeOptions: headerString(response.headers['x-content-type-options']),
        referrerPolicy: headerString(response.headers['referrer-policy']),
        permissionsPolicy: headerString(response.headers['permissions-policy']),
      }),
      ...evaluateCookies(response.headers['set-cookie'], isHttps),
    ];

    // validateScanTarget already confirmed (via HEAD) that finalUrl isn't itself a redirect;
    // a GET landing on one anyway means this server behaves differently for GET vs HEAD. We
    // don't chase it further — that would mean re-entering redirect-following outside
    // validateScanTarget's guarded loop — but the report should say so plainly rather than
    // silently scoring headers from an intermediate hop as if they were final.
    if (response.statusCode >= 300 && response.statusCode < 400) {
      findings.push({
        id: 'headers.unexpected-redirect',
        label: 'Unexpected redirect on GET',
        status: 'warning',
        explanation:
          'The target returned a redirect on this GET request after already resolving as a non-redirect during validation. The headers above are from that redirect response, not a final page.',
        details: { statusCode: response.statusCode },
      });
    }

    return { url: finalUrl.toString(), scannedAt, findings };
  } catch (err) {
    return connectionFailureResult(url, scannedAt, err);
  }
}
