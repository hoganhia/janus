import type { ScanCheckStatus, ScanFinding } from '@janus/shared';
import { joinTxtRecord, lookupTxt } from './dns-lookup.js';

const SPF_LOOKUP_LIMIT = 10;

function isSpfRecord(value: string): boolean {
  return /^v=spf1(\s|$)/i.test(value.trim());
}

/** Simplified count of this record's own lookup-triggering mechanisms — does not recursively
 * follow "include:" chains into other domains' SPF records, so it can undercount the true
 * total the SPF specification's 10-lookup limit applies to. */
function countLookupMechanisms(record: string): number {
  const lookupPattern = /^(include:|a(:|\/|$)|mx(:|\/|$)|ptr(:|$)|exists:|redirect=)/i;
  return record
    .trim()
    .split(/\s+/)
    .filter((term) => lookupPattern.test(term.replace(/^[+\-~?]/, ''))).length;
}

function findAllQualifier(record: string): string | undefined {
  for (const term of record.trim().split(/\s+/)) {
    const match = /^([+\-~?]?)all$/i.exec(term);
    if (match) return match[1] === '' ? '+' : match[1];
  }
  return undefined;
}

/** Fetches and evaluates the domain's SPF record (a TXT record starting with "v=spf1"). */
export async function evaluateSpf(domain: string): Promise<ScanFinding> {
  const result = await lookupTxt(domain);

  if (result.status === 'error') {
    return {
      id: 'dns.spf',
      label: 'SPF record',
      status: 'warning',
      explanation: `Could not check for an SPF record on ${domain}: ${result.message}.`,
      details: { code: result.code },
    };
  }

  const spfRecords = (result.status === 'found' ? result.records.map(joinTxtRecord) : []).filter(
    isSpfRecord,
  );

  if (spfRecords.length === 0) {
    return {
      id: 'dns.spf',
      label: 'SPF record',
      status: 'fail',
      explanation: `${domain} does not have an SPF record, so nothing tells receiving mail servers which servers are allowed to send email as this domain.`,
      recommendation: `Add a TXT record to ${domain} listing your legitimate mail servers, ending in "-all", e.g. \`v=spf1 include:_spf.yourprovider.com -all\`.`,
    };
  }

  if (spfRecords.length > 1) {
    return {
      id: 'dns.spf',
      label: 'SPF record',
      status: 'fail',
      explanation: `${domain} has ${String(spfRecords.length)} SPF records. Having more than one is invalid under the SPF specification, and mail servers may reject or ignore all of them.`,
      recommendation:
        'Merge the multiple SPF records into a single TXT record — SPF only allows one per domain.',
      details: { records: spfRecords },
    };
  }

  const record = spfRecords[0] ?? '';
  const allQualifier = findAllQualifier(record);
  const lookupCount = countLookupMechanisms(record);

  const issues: string[] = [];
  const fixes: string[] = [];
  let status: ScanCheckStatus = 'pass';

  if (allQualifier === undefined) {
    issues.push(
      'does not end with an "all" mechanism, leaving its policy for unlisted senders undefined',
    );
    fixes.push('add "-all" to the end of the record');
    status = 'warning';
  } else if (allQualifier === '+') {
    issues.push('ends with "+all", which explicitly allows any server to send mail as this domain');
    fixes.push('change "+all" to "-all" (hard fail) — "+all" defeats the purpose of SPF');
    status = 'fail';
  } else if (allQualifier === '?') {
    issues.push('ends with "?all" (neutral), which provides no real enforcement');
    fixes.push('change "?all" to "-all" (hard fail) for real enforcement');
    status = 'warning';
  } else if (allQualifier === '~') {
    issues.push('ends with "~all" (soft fail) rather than the stricter "-all" (hard fail)');
    fixes.push('change "~all" to "-all" once you are confident all legitimate senders are listed');
    status = 'warning';
  }

  if (lookupCount > SPF_LOOKUP_LIMIT) {
    issues.push(
      `appears to require more than ${String(SPF_LOOKUP_LIMIT)} DNS lookups to evaluate (counting only this record, not mechanisms nested inside "include:" chains), which risks a PermError under the SPF specification`,
    );
    fixes.push(
      'reduce the number of "include:"/"a"/"mx"/"ptr"/"exists" mechanisms, or flatten some includes into static IP ranges',
    );
    status = 'fail';
  }

  return {
    id: 'dns.spf',
    label: 'SPF record',
    status,
    explanation:
      issues.length === 0
        ? `${domain} has a valid SPF record ending in "-all" (hard fail).`
        : `${domain} has an SPF record, but it ${issues.join('; and it ')}.`,
    ...(fixes.length > 0 ? { recommendation: fixes.join('; ') + '.' } : {}),
    details: { record, lookupCount },
  };
}
