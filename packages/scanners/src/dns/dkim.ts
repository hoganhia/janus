import type { ScanFinding } from '@janus/shared';
import { joinTxtRecord, lookupTxt } from './dns-lookup.js';

/** DKIM selectors are chosen freely by whoever configures mail sending, so this list is
 * inherently a best-effort guess at commonly used names, not exhaustive. */
export const COMMON_DKIM_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  'dkim',
  'mail',
  'smtp',
  'mandrill',
  'amazonses',
];

/** Requires actual key material in the `p=` tag — an empty `p=` explicitly means the key has
 * been revoked (RFC 6376 §3.6.1), which is not a working DKIM record even though the tag is
 * present. Verified against a real, if unusual, case: example.com's wildcard DNS returns
 * `v=DKIM1; p=` for every selector, which a presence-only check would wrongly count as found. */
function looksLikeDkimRecord(value: string): boolean {
  const match = /(^|;)\s*p=([^;]*)/i.exec(value);
  const key = match?.[2]?.trim();
  return key !== undefined && key !== '';
}

/** Checks a fixed list of commonly used DKIM selectors under `<selector>._domainkey.<domain>`.
 * A "pass" here confirms DKIM is configured; a "warning" (not "fail") on finding nothing
 * reflects that DKIM could still be configured under a selector name outside this list —
 * absence of evidence isn't evidence of absence for a value this arbitrary. */
export async function evaluateDkim(
  domain: string,
  selectors: readonly string[] = COMMON_DKIM_SELECTORS,
): Promise<ScanFinding> {
  const results = await Promise.all(
    selectors.map(async (selector) => {
      const result = await lookupTxt(`${selector}._domainkey.${domain}`);
      return { selector, result };
    }),
  );

  const found = results.filter(
    ({ result }) =>
      result.status === 'found' && result.records.map(joinTxtRecord).some(looksLikeDkimRecord),
  );
  const lookupErrors = results
    .filter(({ result }) => result.status === 'error')
    .map(({ selector }) => selector);

  if (found.length > 0) {
    const selectorNames = found.map(({ selector }) => selector);
    const extra = selectorNames.length > 1 ? ` (and ${String(selectorNames.length - 1)} more)` : '';
    return {
      id: 'dns.dkim',
      label: 'DKIM record',
      status: 'pass',
      explanation: `Found a DKIM record for ${domain} under selector "${selectorNames[0] ?? ''}"${extra}.`,
      details: { selectorsFound: selectorNames, selectorsChecked: [...selectors] },
    };
  }

  return {
    id: 'dns.dkim',
    label: 'DKIM record',
    status: 'warning',
    explanation: `No DKIM record was found for ${domain} under any of the ${String(selectors.length)} commonly used selector names checked (${selectors.join(', ')}). This does not necessarily mean DKIM isn't configured — the real selector name can't be discovered passively without a signed email or the domain's mail configuration.`,
    details: { selectorsChecked: [...selectors], lookupErrors },
  };
}
