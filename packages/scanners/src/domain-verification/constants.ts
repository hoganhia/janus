import type { DomainVerificationMethod } from '@janus/db';

export const VERIFICATION_TXT_RECORD_PREFIX = '_janus-verify';
export const WELL_KNOWN_VERIFICATION_PATH = '/.well-known/janus-verify.txt';

/** Re-verification is required every 90 days — see the scheduled expiry job in
 * packages/workers/src/domain-verification-expiry. */
export const VERIFICATION_EXPIRY_DAYS = 90;

export function verificationTxtRecordName(domain: string): string {
  return `${VERIFICATION_TXT_RECORD_PREFIX}.${domain}`;
}

export type VerificationInstructions =
  | { method: 'DNS_TXT'; recordName: string; recordType: 'TXT'; recordValue: string }
  | { method: 'WELL_KNOWN_FILE'; url: string; fileContent: string };

/** Builds the human-readable instructions for whichever challenge method was chosen — what the
 * API returns from the "start verification" endpoint for the caller to actually go set up. */
export function buildVerificationInstructions(
  domain: string,
  method: DomainVerificationMethod,
  token: string,
): VerificationInstructions {
  if (method === 'DNS_TXT') {
    return {
      method,
      recordName: verificationTxtRecordName(domain),
      recordType: 'TXT',
      recordValue: token,
    };
  }
  return { method, url: `https://${domain}${WELL_KNOWN_VERIFICATION_PATH}`, fileContent: token };
}
