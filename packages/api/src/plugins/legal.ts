import { hasAcceptedLatestLegalVersion } from '@janus/db';
import type { FastifyReply, FastifyRequest } from 'fastify';

/**
 * Requires the caller (already authenticated by `requireAuth`, which must run first) to have
 * accepted the current Terms of Service and Acceptable Use Policy before proceeding. This app
 * has no dedicated "signup" flow — Clerk owns the actual account creation UI, and this app
 * never sees a distinct signup event — so acceptance is enforced at the first account-tied
 * action instead: starting domain-ownership verification (see domain-verification.ts). See
 * LEGAL_REVIEW.md for why this scoping decision, and the placeholder text it is gating access
 * to, both still need review before launch.
 */
export async function requireLegalAcceptance(request: FastifyRequest, reply: FastifyReply) {
  // requireAuth must run first (as an earlier preHandler) — see its own doc comment.
  const userId = request.authUserId as string;

  const [acceptedTerms, acceptedAcceptableUse] = await Promise.all([
    hasAcceptedLatestLegalVersion(userId, 'TERMS_OF_SERVICE'),
    hasAcceptedLatestLegalVersion(userId, 'ACCEPTABLE_USE_POLICY'),
  ]);

  if (!acceptedTerms || !acceptedAcceptableUse) {
    return reply.status(403).send({
      error: 'Forbidden',
      message:
        'You must accept the current Terms of Service and Acceptable Use Policy before verifying domain ownership. See GET /api/v1/legal/versions and POST /api/v1/legal/accept.',
    });
  }
  return undefined;
}
