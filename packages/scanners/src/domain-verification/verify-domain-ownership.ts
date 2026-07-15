import type { DomainVerificationMethod } from '@janus/db';
import { checkDnsTxtChallenge, type DnsChallengeOptions } from './dns-challenge.js';
import {
  checkWellKnownFileChallenge,
  type WellKnownChallengeOptions,
} from './well-known-challenge.js';

export type VerifyDomainOwnershipOptions = DnsChallengeOptions & WellKnownChallengeOptions;

/**
 * Dispatches to the DNS TXT or well-known-file ownership check based on `method`. Never throws
 * — both underlying checks already treat every failure mode (DNS error, connection failure,
 * non-matching content) as "not verified" rather than an exception, so a caller can always
 * treat a `false` result as "run the failed-verification path," not "something broke."
 */
export async function verifyDomainOwnership(
  domain: string,
  method: DomainVerificationMethod,
  token: string,
  options: VerifyDomainOwnershipOptions,
): Promise<boolean> {
  if (method === 'DNS_TXT') return checkDnsTxtChallenge(domain, token, options);
  return checkWellKnownFileChallenge(domain, token, options);
}
