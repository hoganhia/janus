import dns from 'node:dns';

// Same cancellation idiom as packages/scanners/src/dns/dns-lookup.ts (not reused directly —
// @janus/shared must not depend on @janus/scanners, which depends on it) — dns.promises has no
// built-in per-query timeout, and Resolver.cancel() reliably aborts a pending query rather than
// waiting out Node's own retry schedule.
const DEFAULT_TIMEOUT_MS = 5000;

const OPT_OUT_LABEL_PREFIX = '_janus-opt-out.';

export interface CheckOptOutOptions {
  timeoutMs?: number;
}

/**
 * Robots.txt-style self-service opt-out: any site owner can add
 * `_janus-opt-out.<their-domain> TXT "true"` to their own DNS zone to block future scans,
 * without needing to contact us or prove ownership through the verification flow (see
 * packages/scanners/src/domain-verification for that separate, stronger mechanism). Fails open
 * (returns false, i.e. "not opted out") on any DNS error or timeout — a resolver hiccup or a
 * domain with no such record must never itself block a scan, the same way a crawler proceeds
 * when robots.txt is unreachable rather than treating that as an implicit disallow.
 */
export async function checkOptOut(
  hostname: string,
  options: CheckOptOutOptions = {},
): Promise<boolean> {
  const resolver = new dns.promises.Resolver();
  const timer = setTimeout(() => {
    resolver.cancel();
  }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  try {
    const records = await resolver.resolveTxt(`${OPT_OUT_LABEL_PREFIX}${hostname.toLowerCase()}`);
    return records.some((chunks) => chunks.join('').trim().toLowerCase() === 'true');
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
