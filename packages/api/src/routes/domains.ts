import { findDomainByName, getScanReportHistory } from '@janus/db';
import type { FastifyPluginCallbackZod } from 'fastify-type-provider-zod';
// See the comment in ../schemas.ts on why this is 'zod/v4' rather than the classic 'zod' import.
import { z } from 'zod/v4';
import {
  domainParamSchema,
  domainVerificationMethodSchema,
  domainVerificationStatusSchema,
  letterGradeSchema,
  scanTierSchema,
} from '../schemas.js';

const DEFAULT_HISTORY_LIMIT = 20;
const MAX_HISTORY_LIMIT = 50;

const domainHistoryQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(MAX_HISTORY_LIMIT).optional(),
});

const scanReportSummarySchema = z.object({
  id: z.string(),
  scannedAt: z.string(),
  overallScore: z.number(),
  overallGrade: letterGradeSchema,
  rawResults: z.unknown(),
  computedScore: z.unknown(),
});

const domainHistoryResponseSchema = z.object({
  domain: z.string(),
  scans: z.array(scanReportSummarySchema),
});

const domainVerificationStatusResponseSchema = z.object({
  domain: z.string(),
  status: domainVerificationStatusSchema,
  method: domainVerificationMethodSchema.nullable(),
  scanTier: scanTierSchema,
  verifiedAt: z.string().nullable(),
  verificationExpiresAt: z.string().nullable(),
});

/**
 * Both routes here are public, unauthenticated by design: a domain's past scan scores/grades
 * and its current verification tier are the kind of transparency information tools like SSL
 * Labs already surface for any domain without a login, and neither is scoped to a particular
 * account — see Prompt 5's auth-scoping decision. Contrast with
 * packages/api/src/routes/domain-verification.ts, which starts or checks a verification
 * challenge (an account-tied action that reveals a live token) and is auth-gated.
 */
export const domainRoutes: FastifyPluginCallbackZod = (app) => {
  app.get(
    '/domains/:domain/history',
    {
      schema: {
        tags: ['domains'],
        summary: 'Past scan history for a domain',
        params: domainParamSchema,
        querystring: domainHistoryQuerySchema,
        response: {
          200: domainHistoryResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { domain } = request.params;
      const { limit } = request.query;

      const reports = await getScanReportHistory(domain, {
        limit: limit ?? DEFAULT_HISTORY_LIMIT,
      });

      return reply.status(200).send({
        domain,
        scans: reports.map((report) => ({
          id: report.id,
          scannedAt: report.scannedAt.toISOString(),
          overallScore: report.overallScore,
          overallGrade: report.overallGrade,
          rawResults: report.rawResults,
          computedScore: report.computedScore,
        })),
      });
    },
  );

  app.get(
    '/domains/:domain/verification',
    {
      schema: {
        tags: ['domains'],
        summary: "A domain's current ownership-verification status and scan tier",
        params: domainParamSchema,
        response: {
          200: domainVerificationStatusResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { domain } = request.params;
      const domainRow = await findDomainByName(domain);

      if (domainRow === null) {
        return reply.status(200).send({
          domain,
          status: 'UNVERIFIED',
          method: null,
          scanTier: 'PASSIVE',
          verifiedAt: null,
          verificationExpiresAt: null,
        });
      }

      return reply.status(200).send({
        domain: domainRow.domain,
        status: domainRow.verificationStatus,
        method: domainRow.verificationMethod,
        scanTier: domainRow.scanTier,
        verifiedAt: domainRow.verifiedAt?.toISOString() ?? null,
        verificationExpiresAt: domainRow.verificationExpiresAt?.toISOString() ?? null,
      });
    },
  );
};
