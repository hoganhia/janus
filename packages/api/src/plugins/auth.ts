import { getAuth } from '@clerk/fastify';
import type { FastifyReply, FastifyRequest } from 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * The verified Clerk user ID of the authenticated caller, set by `requireAuth`. Only
     * guaranteed to be present on routes that use `requireAuth` as a preHandler — routes that
     * don't require auth should not read this.
     */
    authUserId?: string;
  }
}

/**
 * Verifies the caller's Clerk session and rejects with 401 if there isn't a signed-in user.
 * Session parsing itself happens earlier, in `clerkPlugin`'s own global preHandler hook (see
 * app.ts) — by the time this runs, `getAuth(request)` just reads whatever that hook already
 * attached; there's no separate token-verification step here. Deliberately rolling nothing of
 * our own here: password/session handling from scratch is exactly the class of vulnerability
 * this delegates to Clerk to avoid.
 *
 * On success, attaches the verified user ID to `request.authUserId` so downstream handlers
 * (ownership checks, per-account rate limiting) never have to re-parse the session themselves.
 */
export async function requireAuth(request: FastifyRequest, reply: FastifyReply) {
  const auth = getAuth(request);
  if (auth.userId === null) {
    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'A valid session is required for this endpoint.',
    });
  }
  request.authUserId = auth.userId;
  return undefined;
}
