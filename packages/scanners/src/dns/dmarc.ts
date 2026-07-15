import type { ScanCheckStatus, ScanFinding } from '@janus/shared';
import { joinTxtRecord, lookupTxt } from './dns-lookup.js';

function isDmarcRecord(value: string): boolean {
  return /^v=DMARC1(;|\s|$)/i.test(value.trim());
}

function parseDmarcTags(record: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of record.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (key !== '') tags.set(key, value);
  }
  return tags;
}

/** Fetches and evaluates the domain's DMARC record (`_dmarc.<domain>` TXT, `v=DMARC1`). */
export async function evaluateDmarc(domain: string): Promise<ScanFinding> {
  const name = `_dmarc.${domain}`;
  const result = await lookupTxt(name);

  if (result.status === 'error') {
    return {
      id: 'dns.dmarc',
      label: 'DMARC record',
      status: 'warning',
      explanation: `Could not check for a DMARC record on ${domain}: ${result.message}.`,
      details: { code: result.code },
    };
  }

  const dmarcRecords = (result.status === 'found' ? result.records.map(joinTxtRecord) : []).filter(
    isDmarcRecord,
  );

  if (dmarcRecords.length === 0) {
    return {
      id: 'dns.dmarc',
      label: 'DMARC record',
      status: 'fail',
      explanation: `${domain} does not have a DMARC record, so it has no policy telling mail providers what to do with messages that fail SPF or DKIM checks.`,
      recommendation: `Add a TXT record at _dmarc.${domain}, starting with a monitoring-only policy to be safe, e.g. \`v=DMARC1; p=none; rua=mailto:you@${domain}\`, then move to p=quarantine or p=reject once you've reviewed reports.`,
    };
  }

  const record = dmarcRecords[0] ?? '';
  const tags = parseDmarcTags(record);
  const policy = tags.get('p');
  const pctRaw = tags.get('pct');
  const pct = pctRaw !== undefined ? Number(pctRaw) : 100;
  const pctIsPartial = !Number.isNaN(pct) && pct < 100;

  let status: ScanCheckStatus;
  let policyDescription: string;
  let recommendation: string | undefined;
  if (policy === 'reject') {
    status = 'pass';
    policyDescription = 'reject (the strictest policy — non-compliant mail is blocked)';
  } else if (policy === 'quarantine') {
    status = 'pass';
    policyDescription = 'quarantine (non-compliant mail is treated as spam)';
  } else if (policy === 'none') {
    status = 'warning';
    policyDescription = 'none (monitoring only — messages that fail checks are still delivered)';
    recommendation =
      'Once you have reviewed DMARC reports and confirmed legitimate mail passes, move the policy to p=quarantine or p=reject.';
  } else {
    status = 'fail';
    policyDescription = `an unrecognized or missing value ("${policy ?? ''}")`;
    recommendation = 'Set the DMARC record\'s "p" tag to one of: none, quarantine, or reject.';
  }

  if (pctIsPartial && status === 'pass') {
    status = 'warning';
    recommendation =
      'Increase pct to 100 once you are confident the policy is not causing false positives.';
  }

  const pctNote = pctIsPartial ? ` (applied to only ${String(pct)}% of messages)` : '';

  return {
    id: 'dns.dmarc',
    label: 'DMARC record',
    status,
    explanation: `${domain} has a DMARC record with policy ${policyDescription}${pctNote}.`,
    ...(recommendation !== undefined ? { recommendation } : {}),
    details: { record, policy: policy ?? null, pct },
  };
}
