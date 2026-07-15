import {
  findDomainByName,
  markDomainVerificationFailed,
  markDomainVerified,
  startDomainVerification,
} from '@janus/db';
import {
  buildVerificationInstructions,
  generateVerificationToken,
  VERIFICATION_EXPIRY_DAYS,
  verifyDomainOwnership,
} from '@janus/scanners';
import type { FastifyPluginCallbackZod } from 'fastify-type-provider-zod';
// See the comment in ../schemas.ts on why this is 'zod/v4' rather than the classic 'zod' import.
import { z } from 'zod/v4';
import { requireAuth } from '../plugins/auth.js';
import { requireLegalAcceptance } from '../plugins/legal.js';
import {
  domainParamSchema,
  domainVerificationMethodSchema,
  domainVerificationStatusSchema,
  errorResponseSchema,
  scanTierSchema,
} from '../schemas.js';

export interface DomainVerificationRoutesOptions {
  /** Sent as the User-Agent on the outbound well-known-file check — see SCANNER_USER_AGENT. */
  scannerUserAgent: string;
}

/**
 * Both routes here start or resolve a live challenge — starting one hands back a token the
 * caller needs to go publish, and checking one immediately consumes it — so, unlike the public
 * status/history routes in domains.ts, both are auth-gated: an anonymous caller shouldn't be
 * able to spin up (or burn through retries on) a verification challenge for a domain they don't
 * control. Same reasoning Prompt 5 applied to scan creation.
 */
const VERIFICATION_RATE_LIMIT_MAX = 10;
const VERIFICATION_RATE_LIMIT_TIME_WINDOW_MS = 60 * 60 * 1000;

const startVerificationBodySchema = z.object({
  method: domainVerificationMethodSchema,
});

const startVerificationResponseSchema = z.object({
  domain: z.string(),
  status: domainVerificationStatusSchema,
  instructions: z.union([
    z.object({
      method: z.literal('DNS_TXT'),
      recordName: z.string(),
      recordType: z.literal('TXT'),
      recordValue: z.string(),
    }),
    z.object({
      method: z.literal('WELL_KNOWN_FILE'),
      url: z.string(),
      fileContent: z.string(),
    }),
  ]),
});

const checkVerificationResponseSchema = z.object({
  domain: z.string(),
  status: domainVerificationStatusSchema,
  scanTier: scanTierSchema,
  verifiedAt: z.string().nullable(),
  verificationExpiresAt: z.string().nullable(),
});

function addDays(base: Date, days: number): Date {
  return new Date(base.getTime() + days * 24 * 60 * 60 * 1000);
}

export const domainVerificationRoutes: FastifyPluginCallbackZod<DomainVerificationRoutesOptions> = (
  app,
  options,
) => {
  app.post(
    '/domains/:domain/verification',
    {
      // requireLegalAcceptance must run after requireAuth — it reads request.authUserId, which
      // requireAuth sets. See requireLegalAcceptance's own doc comment for why this is where
      // ToS/AUP acceptance is enforced, rather than at some dedicated "signup" step this app
      // doesn't have.
      preHandler: [requireAuth, requireLegalAcceptance],
      config: {
        rateLimit: {
          max: VERIFICATION_RATE_LIMIT_MAX,
          timeWindow: VERIFICATION_RATE_LIMIT_TIME_WINDOW_MS,
        },
      },
      schema: {
        tags: ['domains'],
        summary: 'Start a domain-ownership verification challenge',
        params: domainParamSchema,
        body: startVerificationBodySchema,
        response: {
          200: startVerificationResponseSchema,
          401: errorResponseSchema,
          403: errorResponseSchema,
          429: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { domain } = request.params;
      const { method } = request.body;
      const token = generateVerificationToken();

      const domainRow = await startDomainVerification(domain, method, token);

      return reply.status(200).send({
        domain: domainRow.domain,
        status: domainRow.verificationStatus,
        instructions: buildVerificationInstructions(domainRow.domain, method, token),
      });
    },
  );

  app.post(
    '/domains/:domain/verification/check',
    {
      preHandler: [requireAuth],
      config: {
        rateLimit: {
          max: VERIFICATION_RATE_LIMIT_MAX,
          timeWindow: VERIFICATION_RATE_LIMIT_TIME_WINDOW_MS,
        },
      },
      schema: {
        tags: ['domains'],
        summary: 'Check a pending domain-ownership verification challenge',
        params: domainParamSchema,
        response: {
          200: checkVerificationResponseSchema,
          400: errorResponseSchema,
          401: errorResponseSchema,
          429: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { domain } = request.params;

      const domainRow = await findDomainByName(domain);
      if (
        domainRow === null ||
        domainRow.verificationToken === null ||
        domainRow.verificationMethod === null
      ) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'No verification challenge is in progress for this domain. Start one first.',
        });
      }

      const verified = await verifyDomainOwnership(
        domainRow.domain,
        domainRow.verificationMethod,
        domainRow.verificationToken,
        { requesterIp: request.ip, userAgent: options.scannerUserAgent },
      );

      const updated = verified
        ? await markDomainVerified(domainRow.id, {
            verifiedAt: new Date(),
            expiresAt: addDays(new Date(), VERIFICATION_EXPIRY_DAYS),
          })
        : await markDomainVerificationFailed(domainRow.id);

      return reply.status(200).send({
        domain: updated.domain,
        status: updated.verificationStatus,
        scanTier: updated.scanTier,
        verifiedAt: updated.verifiedAt?.toISOString() ?? null,
        verificationExpiresAt: updated.verificationExpiresAt?.toISOString() ?? null,
      });
    },
  );
};
