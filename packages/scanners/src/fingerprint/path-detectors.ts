/**
 * Deliberately a small, fixed list — no brute-forcing or path guessing. Each entry is a single,
 * well-known static path a passive scanner can check safely. This module only defines what to
 * look for and how to interpret a response; the actual (pinned, SSRF-safe) HTTP requests are
 * made by the orchestrator in scan-fingerprint.ts.
 */
export interface PathCheckDefinition {
  path: string;
  productKey: string;
  label: string;
  /** Status codes that mean "this path exists on the server" — some servers 403 a path that's
   * present but not publicly listable, which still confirms presence. */
  presenceStatusCodes: readonly number[];
  /** Only called when the response body was captured and the status indicated presence. */
  extractVersion?: (body: string) => string | undefined;
}

function extractWordPressReadmeVersion(body: string): string | undefined {
  // WordPress's default readme.html has included a "Version X.Y.Z" line near the top since
  // its earliest releases — the same technique long-established passive WP scanners use.
  return /Version\s+([\d.]+)/i.exec(body)?.[1];
}

export const PATH_CHECKS: readonly PathCheckDefinition[] = [
  {
    path: '/wp-login.php',
    productKey: 'wordpress',
    label: 'WordPress login page',
    presenceStatusCodes: [200, 401, 403],
  },
  {
    path: '/readme.html',
    productKey: 'wordpress',
    label: 'WordPress readme file',
    presenceStatusCodes: [200],
    extractVersion: extractWordPressReadmeVersion,
  },
  {
    path: '/_next/static/',
    productKey: 'nextjs',
    label: 'Next.js static asset directory',
    presenceStatusCodes: [200, 403],
  },
];

/** Checked for general technology-signal purposes only — `/vendor/` presence doesn't identify
 * a specific, CVE-trackable product+version, so it never feeds CVE cross-referencing. */
export interface GenericPathCheck {
  path: string;
  label: string;
  presenceStatusCodes: readonly number[];
}

export const GENERIC_TECH_PATH_CHECKS: readonly GenericPathCheck[] = [
  { path: '/vendor/', label: 'PHP Composer dependency directory', presenceStatusCodes: [200, 403] },
];

export interface PathDetection {
  productKey: string;
  version: string | undefined;
  path: string;
  label: string;
}

export function evaluatePathCheck(
  check: PathCheckDefinition,
  statusCode: number,
  body: Buffer | undefined,
): PathDetection | undefined {
  if (!check.presenceStatusCodes.includes(statusCode)) return undefined;
  const version =
    check.extractVersion !== undefined && body !== undefined
      ? check.extractVersion(body.toString('utf8'))
      : undefined;
  return { productKey: check.productKey, version, path: check.path, label: check.label };
}
