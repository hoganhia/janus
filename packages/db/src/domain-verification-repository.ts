import { getPrismaClient } from './client.js';
import type { Domain, DomainVerificationMethod } from './generated/prisma/client.js';

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase();
}

/**
 * Looks up a `Domain` row by name without creating one — unlike `findOrCreateDomain`, a plain
 * status check (e.g. "has this domain ever been verified?") shouldn't conjure a row into
 * existence just by being asked about it.
 */
export async function findDomainByName(domain: string): Promise<Domain | null> {
  const prisma = getPrismaClient();
  return prisma.domain.findUnique({ where: { domain: normalizeDomain(domain) } });
}

/**
 * Records a fresh verification challenge for `domain`, creating the `Domain` row if it doesn't
 * exist yet. Always issues a new token and resets to `PENDING`, even if one is already in
 * progress — re-starting supersedes rather than reuses a prior challenge, so a stale token
 * never lingers as valid. Deliberately does not touch `scanTier`: starting a *new* challenge
 * shouldn't revoke a still-valid AUTHENTICATED tier earned by an earlier, unexpired
 * verification — only a failed check or the scheduled expiry job does that.
 */
export async function startDomainVerification(
  domain: string,
  method: DomainVerificationMethod,
  token: string,
): Promise<Domain> {
  const normalized = normalizeDomain(domain);
  const prisma = getPrismaClient();
  return prisma.domain.upsert({
    where: { domain: normalized },
    create: {
      domain: normalized,
      verificationStatus: 'PENDING',
      verificationMethod: method,
      verificationToken: token,
    },
    update: {
      verificationStatus: 'PENDING',
      verificationMethod: method,
      verificationToken: token,
    },
  });
}

export interface MarkDomainVerifiedInput {
  verifiedAt: Date;
  /** Computed by the caller (see VERIFICATION_EXPIRY_DAYS in
   * @janus/scanners's domain-verification module) — this repository just persists it, the same
   * way `recordScanReport` persists an already-computed grade rather than deriving one. */
  expiresAt: Date;
}

/** Marks a domain as successfully verified and unlocks the AUTHENTICATED scan tier. */
export async function markDomainVerified(
  domainId: string,
  input: MarkDomainVerifiedInput,
): Promise<Domain> {
  const prisma = getPrismaClient();
  return prisma.domain.update({
    where: { id: domainId },
    data: {
      verificationStatus: 'VERIFIED',
      verifiedAt: input.verifiedAt,
      verificationExpiresAt: input.expiresAt,
      scanTier: 'AUTHENTICATED',
    },
  });
}

/**
 * Marks a verification attempt as failed. Does not touch `scanTier` — if this domain already
 * had a still-valid AUTHENTICATED tier from an earlier successful verification, a failed
 * *re*-verification attempt shouldn't revoke it; only expiry does that.
 */
export async function markDomainVerificationFailed(domainId: string): Promise<Domain> {
  const prisma = getPrismaClient();
  return prisma.domain.update({
    where: { id: domainId },
    data: { verificationStatus: 'FAILED' },
  });
}

/**
 * Domains whose successful verification has passed its expiry — the candidate set for the
 * scheduled downgrade job in packages/workers/src/domain-verification-expiry.
 */
export async function findExpiredVerifications(now: Date): Promise<Domain[]> {
  const prisma = getPrismaClient();
  return prisma.domain.findMany({
    where: { verificationStatus: 'VERIFIED', verificationExpiresAt: { lt: now } },
  });
}

/** Downgrades one expired verification: EXPIRED status, back to the PASSIVE scan tier. */
export async function downgradeExpiredVerification(domainId: string): Promise<Domain> {
  const prisma = getPrismaClient();
  return prisma.domain.update({
    where: { id: domainId },
    data: { verificationStatus: 'EXPIRED', scanTier: 'PASSIVE' },
  });
}
