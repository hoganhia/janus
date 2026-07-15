import {
  deleteUserLegalData,
  getCurrentLegalVersion,
  hasAcceptedLatestLegalVersion,
  recordLegalAcceptance,
} from '@janus/db';
import type { FastifyPluginCallbackZod } from 'fastify-type-provider-zod';
// See the comment in ../schemas.ts on why this is 'zod/v4' rather than the classic 'zod' import.
import { z } from 'zod/v4';
import { requireAuth } from '../plugins/auth.js';
import { errorResponseSchema, legalDocumentTypeSchema } from '../schemas.js';

const LEGAL_DOCUMENT_TYPES = legalDocumentTypeSchema.options;
type LegalDocumentTypeLiteral = (typeof LEGAL_DOCUMENT_TYPES)[number];

/**
 * `Object.fromEntries` only ever infers the loose `{ [k: string]: V }` shape, even given a
 * tuple of exact literal keys — this rebuilds the same data with the precise
 * `Record<LegalDocumentTypeLiteral, V>` type each response schema below actually expects.
 */
async function buildLegalDocumentRecord<V>(
  build: (documentType: LegalDocumentTypeLiteral) => Promise<V>,
): Promise<Record<LegalDocumentTypeLiteral, V>> {
  const entries = await Promise.all(
    LEGAL_DOCUMENT_TYPES.map(
      async (documentType) => [documentType, await build(documentType)] as const,
    ),
  );
  return Object.fromEntries(entries) as Record<LegalDocumentTypeLiteral, V>;
}

const legalVersionSchema = z.object({
  version: z.string(),
  effectiveAt: z.string(),
});

const legalVersionsResponseSchema = z.record(legalDocumentTypeSchema, legalVersionSchema);

const acceptBodySchema = z.object({
  documentType: legalDocumentTypeSchema,
});

const acceptResponseSchema = z.object({
  documentType: legalDocumentTypeSchema,
  version: z.string(),
  acceptedAt: z.string(),
});

const legalStatusResponseSchema = z.record(legalDocumentTypeSchema, z.boolean());

const deleteAccountResponseSchema = z.object({
  scanConsents: z.number(),
  legalAcceptances: z.number(),
});

/**
 * Public — a page like /terms needs to display which version it's showing without requiring
 * login, and (like /health, /domains/:domain/history, and scan submission before it) must keep
 * working even if Clerk is misconfigured. Registered outside the Clerk-scoped block in app.ts
 * for exactly that reason — see legalRoutes below for the auth-gated actions.
 */
export const legalVersionsRoutes: FastifyPluginCallbackZod = (app) => {
  app.get(
    '/legal/versions',
    {
      schema: {
        tags: ['legal'],
        summary: 'The current version of each legal document',
        response: {
          200: legalVersionsResponseSchema,
        },
      },
    },
    async (_request, reply) => {
      const versions = await buildLegalDocumentRecord(async (documentType) => {
        const version = await getCurrentLegalVersion(documentType);
        return { version: version.version, effectiveAt: version.effectiveAt.toISOString() };
      });
      return reply.status(200).send(versions);
    },
  );
};

/**
 * Every route here acts on the caller's own account, so all three are auth-gated the same way
 * domain-verification is (see requireAuth's doc comment) — there's no ownership check beyond
 * "you are who your Clerk session says you are," since every action here only ever touches the
 * caller's own rows. Must be registered inside the Clerk-scoped block in app.ts (alongside
 * domainVerificationRoutes) since requireAuth needs clerkPlugin's preHandler hook to have
 * already run in the same Fastify encapsulation scope.
 *
 * All legal document *text* referenced by version here is placeholder content pending legal
 * review — see LEGAL_REVIEW.md at the repo root. Nothing in this route file is itself
 * launch-blocking; the text it points at is.
 */
export const legalRoutes: FastifyPluginCallbackZod = (app) => {
  app.post(
    '/legal/accept',
    {
      preHandler: [requireAuth],
      schema: {
        tags: ['legal'],
        summary: 'Record that the caller has accepted the current version of a legal document',
        body: acceptBodySchema,
        response: {
          200: acceptResponseSchema,
          401: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { documentType } = request.body;
      // requireAuth guarantees this is set — see its own doc comment.
      const userId = request.authUserId as string;

      const acceptance = await recordLegalAcceptance({
        userId,
        documentType,
        ipAddress: request.ip,
      });
      const version = await getCurrentLegalVersion(documentType);

      return reply.status(200).send({
        documentType,
        version: version.version,
        acceptedAt: acceptance.acceptedAt.toISOString(),
      });
    },
  );

  app.get(
    '/legal/status',
    {
      preHandler: [requireAuth],
      schema: {
        tags: ['legal'],
        summary: 'Whether the caller has accepted the current version of each legal document',
        response: {
          200: legalStatusResponseSchema,
          401: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const userId = request.authUserId as string;
      const status = await buildLegalDocumentRecord((documentType) =>
        hasAcceptedLatestLegalVersion(userId, documentType),
      );
      return reply.status(200).send(status);
    },
  );

  app.post(
    '/legal/delete-account',
    {
      preHandler: [requireAuth],
      schema: {
        tags: ['legal'],
        summary: 'Delete the caller’s own consent and legal-acceptance records',
        response: {
          200: deleteAccountResponseSchema,
          401: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const userId = request.authUserId as string;
      const result = await deleteUserLegalData(userId);

      // Record type + count only, never the deleted content itself — see Prompt 9's own
      // requirement and the matching pattern in the data-retention scheduled job.
      request.log.info(
        { scanConsents: result.scanConsents, legalAcceptances: result.legalAcceptances },
        'User-requested account data deletion completed',
      );

      return reply.status(200).send(result);
    },
  );
};
