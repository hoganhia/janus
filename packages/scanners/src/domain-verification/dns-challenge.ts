import { joinTxtRecord, lookupTxt } from '../dns/dns-lookup.js';
import { verificationTxtRecordName } from './constants.js';

export interface DnsChallengeOptions {
  /** Default: 5000 (dns-lookup.ts's own default). */
  timeoutMs?: number;
}

/**
 * Checks whether `_janus-verify.<domain>` has a TXT record whose value exactly matches `token`.
 * A DNS query to a trusted resolver, not a connection to an address derived from the target —
 * same reasoning as `scanDNS` for why this doesn't go through `validateScanTarget` (see
 * packages/scanners/src/dns/scan-dns.ts's doc comment). Never throws: NXDOMAIN, no data, and
 * timeouts all just mean "not verified."
 */
export async function checkDnsTxtChallenge(
  domain: string,
  token: string,
  options: DnsChallengeOptions = {},
): Promise<boolean> {
  const result = await lookupTxt(
    verificationTxtRecordName(domain),
    options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {},
  );
  if (result.status !== 'found') return false;
  return result.records.some((chunks) => joinTxtRecord(chunks).trim() === token);
}
