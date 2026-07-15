import { downgradeExpiredVerification, findExpiredVerifications } from '@janus/db';

export interface ExpireDomainVerificationsResult {
  checkedAt: string;
  expiredCount: number;
  domains: string[];
}

/**
 * Downgrades every domain whose successful verification has passed its 90-day expiry: EXPIRED
 * status, back to the PASSIVE scan tier (see `Domain.verificationExpiresAt` in
 * packages/db/prisma/schema.prisma). One domain failing to update doesn't stop the rest — this
 * runs on a schedule, so a domain missed this run gets caught on the next one; only if *every*
 * candidate fails does this throw, so BullMQ's retry/alerting actually notices a systemic
 * problem (e.g. Postgres unreachable) rather than one row's transient error.
 */
export async function expireStaleDomainVerifications(
  now: Date = new Date(),
): Promise<ExpireDomainVerificationsResult> {
  const candidates = await findExpiredVerifications(now);
  const domains: string[] = [];
  const errors: string[] = [];

  for (const candidate of candidates) {
    try {
      await downgradeExpiredVerification(candidate.id);
      domains.push(candidate.domain);
    } catch (err) {
      errors.push(`${candidate.domain}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (candidates.length > 0 && errors.length === candidates.length) {
    throw new Error(
      `Failed to downgrade all ${String(candidates.length)} expired domain verifications: ${errors.join('; ')}`,
    );
  }

  return { checkedAt: now.toISOString(), expiredCount: domains.length, domains };
}
