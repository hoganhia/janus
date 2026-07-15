import type { ScanFinding } from '@janus/shared';
import { queryRawDns, RawDnsQueryError } from './raw-dns-query.js';

/**
 * Checks DNSSEC by presence: does the domain publish DNSKEY records, and does its parent zone
 * have a matching DS record (the secure delegation that makes those keys actually trustworthy
 * to a validating resolver)? This confirms presence, not full cryptographic chain validation
 * (verifying RRSIG signatures against the keys, walking the chain to the root) — that's out of
 * scope for a passive, dependency-light scanner and is called out explicitly in the finding.
 */
export async function evaluateDnssec(domain: string): Promise<ScanFinding> {
  const [dsResult, dnskeyResult] = await Promise.allSettled([
    queryRawDns(domain, 'DS'),
    queryRawDns(domain, 'DNSKEY'),
  ]);

  const dsError = dsResult.status === 'rejected' ? (dsResult.reason as unknown) : undefined;

  if (dsError instanceof RawDnsQueryError && dsError.code === 'NXDOMAIN') {
    return {
      id: 'dns.dnssec',
      label: 'DNSSEC',
      status: 'fail',
      explanation: `${domain} does not exist.`,
    };
  }

  if (dsResult.status === 'rejected' && dnskeyResult.status === 'rejected') {
    return {
      id: 'dns.dnssec',
      label: 'DNSSEC',
      status: 'warning',
      explanation: `Could not check DNSSEC status for ${domain}: ${dsError instanceof Error ? dsError.message : String(dsError)}.`,
    };
  }

  const dsChecked = dsResult.status === 'fulfilled';
  const dnskeyChecked = dnskeyResult.status === 'fulfilled';
  const hasDs = dsChecked && dsResult.value.length > 0;
  const hasDnskey = dnskeyChecked && dnskeyResult.value.length > 0;

  if (!dsChecked || !dnskeyChecked) {
    return {
      id: 'dns.dnssec',
      label: 'DNSSEC',
      status: 'warning',
      explanation: `DNSSEC status for ${domain} could not be fully determined — the ${dsChecked ? 'DNSKEY' : 'DS'} lookup failed while the other succeeded.`,
      details: { hasDs, hasDnskey, dsChecked, dnskeyChecked },
    };
  }

  if (hasDs && hasDnskey) {
    return {
      id: 'dns.dnssec',
      label: 'DNSSEC',
      status: 'pass',
      explanation: `${domain} has both a DS record (a secure delegation from its parent zone) and DNSKEY records, indicating DNSSEC is enabled.`,
      details: { hasDs, hasDnskey },
    };
  }

  if (hasDnskey && !hasDs) {
    return {
      id: 'dns.dnssec',
      label: 'DNSSEC',
      status: 'warning',
      explanation: `${domain} publishes DNSKEY records but has no DS record in its parent zone, so the chain of trust is incomplete — resolvers won't treat it as DNSSEC-validated.`,
      details: { hasDs, hasDnskey },
    };
  }

  return {
    id: 'dns.dnssec',
    label: 'DNSSEC',
    status: 'fail',
    explanation: `${domain} has no DS or DNSKEY records — DNSSEC does not appear to be enabled. (This checks for record presence only, not full cryptographic signature validation.)`,
    details: { hasDs, hasDnskey },
  };
}
