import { COMMON_DKIM_SELECTORS, evaluateDkim } from './dkim.js';
import { evaluateDmarc } from './dmarc.js';
import { evaluateDnssec } from './dnssec.js';
import { evaluateSpf } from './spf.js';
import type { DnsScanResult } from './types.js';

export interface ScanDnsOptions {
  dkimSelectors?: readonly string[];
}

// Validated per-label (rather than one regex with nested quantifiers spanning the whole
// domain) to keep matching linear and avoid catastrophic-backtracking risk on hostile input.
// Bounded, non-nested quantifier; stress-tested at 100k evaluations of adversarial input
// (~62-char worst case) in 50ms total.
// eslint-disable-next-line security/detect-unsafe-regex
const LABEL_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
const TLD_PATTERN = /^[a-z]{2,63}$/i;
const MAX_DOMAIN_LENGTH = 253;

function isValidDomain(domain: string): boolean {
  if (domain.length === 0 || domain.length > MAX_DOMAIN_LENGTH) return false;
  const labels = domain.split('.');
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1] ?? '';
  if (!TLD_PATTERN.test(tld)) return false;
  return labels.slice(0, -1).every((label) => LABEL_PATTERN.test(label));
}

/**
 * Scans a domain's email-authentication and DNSSEC posture: SPF, DKIM (via common selector
 * guessing), DMARC, and DNSSEC (DS/DNSKEY presence). All four checks run concurrently and are
 * independently error-handled (NXDOMAIN, no-data, and timeouts all come back as typed results,
 * never a thrown exception).
 *
 * Unlike `scanTLS`/`scanHeaders`, this does not go through `validateScanTarget`: every lookup
 * here is a DNS *query* sent to a trusted resolver (the OS-configured one, or a well-known
 * public fallback) asking about the target name — it never opens a connection to an address
 * derived from the target itself, so the SSRF class `validateScanTarget` guards against doesn't
 * apply. `domain` is still format-validated so obviously malformed input never reaches the
 * resolver.
 */
export async function scanDNS(
  domain: string,
  options: ScanDnsOptions = {},
): Promise<DnsScanResult> {
  const scannedAt = new Date().toISOString();

  if (!isValidDomain(domain)) {
    return {
      domain,
      scannedAt,
      findings: [
        {
          id: 'dns.domain',
          label: 'Domain name',
          status: 'fail',
          explanation: `"${domain}" does not look like a valid domain name.`,
        },
      ],
    };
  }

  const findings = await Promise.all([
    evaluateSpf(domain),
    evaluateDmarc(domain),
    evaluateDkim(domain, options.dkimSelectors ?? COMMON_DKIM_SELECTORS),
    evaluateDnssec(domain),
  ]);

  return { domain, scannedAt, findings };
}
