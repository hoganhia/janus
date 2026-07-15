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
  if (policy === 'reject') {
    status = 'pass';
    policyDescription = 'reject (the strictest policy — non-compliant mail is blocked)';
  } else if (policy === 'quarantine') {
    status = 'pass';
    policyDescription = 'quarantine (non-compliant mail is treated as spam)';
  } else if (policy === 'none') {
    status = 'warning';
    policyDescription = 'none (monitoring only — messages that fail checks are still delivered)';
  } else {
    status = 'fail';
    policyDescription = `an unrecognized or missing value ("${policy ?? ''}")`;
  }

  if (pctIsPartial && status === 'pass') {
    status = 'warning';
  }

  const pctNote = pctIsPartial ? ` (applied to only ${String(pct)}% of messages)` : '';

  return {
    id: 'dns.dmarc',
    label: 'DMARC record',
    status,
    explanation: `${domain} has a DMARC record with policy ${policyDescription}${pctNote}.`,
    details: { record, policy: policy ?? null, pct },
  };
}
