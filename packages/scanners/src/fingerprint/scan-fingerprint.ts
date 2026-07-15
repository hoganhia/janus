import { findProductByKey } from '@janus/db';
import {
  fetchPinned,
  ScanTargetRejectedError,
  validateScanTarget,
  type ScanFinding,
  type ScanTargetListStore,
} from '@janus/shared';
import { buildCveFindings } from './cve-matching.js';
import { detectFromHeaders } from './header-detectors.js';
import {
  evaluatePathCheck,
  GENERIC_TECH_PATH_CHECKS,
  PATH_CHECKS,
  type PathDetection,
} from './path-detectors.js';
import type { FingerprintScanResult } from './types.js';

export interface FingerprintStackOptions {
  requesterIp: string;
  /** Same requirement as scanHeaders — required, no built-in default. */
  userAgent: string;
  listStore?: ScanTargetListStore;
  maxRedirects?: number;
  headersTimeoutMs?: number;
  bodyTimeoutMs?: number;
  maxBodyBytes?: number;
}

const DEFAULT_MAX_REDIRECTS = 3;
const DEFAULT_TIMEOUT_MS = 5000;
// Smaller than scanHeaders' default — path checks here only ever need to read a small text
// snippet (e.g. a version line near the top of a readme file), never a full page.
const DEFAULT_MAX_BODY_BYTES = 512 * 1024;

const CAVEAT =
  'Software and version detection here is passive and probabilistic: it is based only on what the server voluntarily discloses in HTTP headers and a small, fixed set of well-known static file paths (no path brute-forcing is performed). Headers and files can be spoofed, customized, or removed, and the absence of a signal does not mean a technology is absent. Treat every detection as a hint to verify, not a certainty.';

function headerString(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

interface MergedDetection {
  productKey: string;
  version: string | undefined;
  sources: string[];
}

function mergeDetections(
  headerDetections: { productKey: string; version: string | undefined; source: string }[],
  pathDetections: PathDetection[],
): Map<string, MergedDetection> {
  const byProduct = new Map<string, MergedDetection>();

  const add = (productKey: string, version: string | undefined, source: string) => {
    const existing = byProduct.get(productKey);
    if (existing === undefined) {
      byProduct.set(productKey, { productKey, version, sources: [source] });
    } else {
      existing.sources.push(source);
      existing.version ??= version;
    }
  };

  for (const d of headerDetections) add(d.productKey, d.version, `${d.source} header`);
  for (const d of pathDetections) add(d.productKey, d.version, d.path);

  return byProduct;
}

function connectionFailureResult(
  url: string,
  scannedAt: string,
  err: unknown,
): FingerprintScanResult {
  const reason = err instanceof ScanTargetRejectedError ? err.reason : undefined;
  return {
    url,
    scannedAt,
    caveat: CAVEAT,
    findings: [
      {
        id: 'fingerprint.connection',
        label: 'HTTP connection',
        status: 'fail',
        explanation:
          reason !== undefined
            ? `Could not fingerprint ${url}: the target failed validation (${reason}).`
            : `Could not fingerprint ${url}. The site may be down, blocking scans, or unreachable.`,
        recommendation:
          'Confirm the server responds to standard HTTP(S) requests from external clients — check for a firewall, load balancer, or DNS issue blocking access.',
        details: { error: err instanceof Error ? err.message : String(err) },
      },
    ],
  };
}

/**
 * Passively fingerprints a site's server/framework stack from response headers (Server,
 * X-Powered-By) and a small fixed list of well-known static paths — never brute-forcing paths
 * — then cross-references any detected product+version against the locally cached CVE dataset
 * (`@janus/db`, populated by the scheduled sync job in packages/workers; NVD is never queried
 * live here). Redirects are resolved once via `validateScanTarget`, and every subsequent
 * request (the main page plus each path check) reuses that same validated pinned address — no
 * per-path re-resolution. A single path check failing never aborts the others; the whole scan
 * only comes back as a failure if the initial connection/validation itself fails.
 */
export async function fingerprintStack(
  url: string,
  options: FingerprintStackOptions,
): Promise<FingerprintScanResult> {
  const scannedAt = new Date().toISOString();

  try {
    const validated = await validateScanTarget(url, {
      requesterIp: options.requesterIp,
      maxRedirects: options.maxRedirects ?? DEFAULT_MAX_REDIRECTS,
      userAgent: options.userAgent,
      ...(options.listStore !== undefined ? { listStore: options.listStore } : {}),
    });

    const finalUrl = new URL(validated.finalUrl);
    const fetchOptions = {
      userAgent: options.userAgent,
      headersTimeoutMs: options.headersTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      bodyTimeoutMs: options.bodyTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxBodyBytes: options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
    };

    const mainResponse = await fetchPinned(finalUrl, validated.pinnedAddress, fetchOptions);
    const headerDetections = detectFromHeaders({
      server: headerString(mainResponse.headers['server']),
      xPoweredBy: headerString(mainResponse.headers['x-powered-by']),
    });

    const pathDetections: PathDetection[] = [];
    for (const check of PATH_CHECKS) {
      try {
        const checkUrl = new URL(check.path, finalUrl);
        const response = await fetchPinned(checkUrl, validated.pinnedAddress, {
          ...fetchOptions,
          captureBody: check.extractVersion !== undefined,
        });
        const detection = evaluatePathCheck(check, response.statusCode, response.body);
        if (detection !== undefined) pathDetections.push(detection);
      } catch {
        // One path check failing (timeout, reset) shouldn't abort the rest of the scan.
      }
    }

    const genericFindings: ScanFinding[] = [];
    for (const check of GENERIC_TECH_PATH_CHECKS) {
      try {
        const checkUrl = new URL(check.path, finalUrl);
        const response = await fetchPinned(checkUrl, validated.pinnedAddress, fetchOptions);
        if (check.presenceStatusCodes.includes(response.statusCode)) {
          genericFindings.push({
            id: `fingerprint.path.${check.path}`,
            label: check.label,
            status: 'warning',
            explanation: `Found ${check.label} at ${check.path}. This is a general technology signal, not enough on its own to identify a specific framework or version for CVE matching.`,
            recommendation: `If not needed publicly, restrict or remove access to ${check.path} to reduce what attackers can passively learn about your stack.`,
          });
        }
      } catch {
        // Same as above.
      }
    }

    const merged = mergeDetections(headerDetections, pathDetections);
    const findings: ScanFinding[] = [];

    for (const detection of merged.values()) {
      const productName =
        findProductByKey(detection.productKey)?.displayName ?? detection.productKey;
      findings.push({
        id: `fingerprint.detected.${detection.productKey}`,
        label: `Detected: ${productName}`,
        status: 'warning',
        explanation:
          detection.version !== undefined
            ? `Detected ${productName} version ${detection.version} via ${detection.sources.join(', ')}.`
            : `Detected ${productName} via ${detection.sources.join(', ')}, but no version could be determined.`,
        recommendation: `Consider suppressing version identifiers in ${detection.sources.join(', ')} — publicly disclosing exact versions makes it easier for an attacker to target known vulnerabilities in that specific release.`,
        details: {
          productKey: detection.productKey,
          version: detection.version ?? null,
          sources: detection.sources,
        },
      });

      if (detection.version !== undefined) {
        findings.push(...(await buildCveFindings(detection.productKey, detection.version)));
      }
    }

    findings.push(...genericFindings);

    return { url: finalUrl.toString(), scannedAt, caveat: CAVEAT, findings };
  } catch (err) {
    return connectionFailureResult(url, scannedAt, err);
  }
}
