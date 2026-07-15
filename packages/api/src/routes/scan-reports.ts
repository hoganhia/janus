import { getScanReportById } from '@janus/db';
import type { FastifyPluginCallbackZod } from 'fastify-type-provider-zod';
// See the comment in ../schemas.ts on why this is 'zod/v4' rather than the classic 'zod' import.
import { z } from 'zod/v4';
import { errorResponseSchema, letterGradeSchema } from '../schemas.js';

const scanReportParamsSchema = z.object({
  id: z.string().min(1),
});

const scanReportResponseSchema = z.object({
  id: z.string(),
  domain: z.string(),
  scannedAt: z.string(),
  overallScore: z.number(),
  overallGrade: letterGradeSchema,
  /** The `ScanResults` object (tls/headers/dns/fingerprint findings) passed into `scoreReport`. */
  rawResults: z.unknown(),
  /** The full `ScoreReport` object: per-category grades, overall score, disclaimer. */
  computedScore: z.unknown(),
});

/**
 * Public, unauthenticated by design — same reasoning as `GET /domains/:domain/history`, which
 * this complements: a scan's completed results aren't sensitive, and the ID is an unguessable
 * cuid. This exists because `GET /scans/:id` (the BullMQ job status endpoint) only returns a
 * thin summary and stops working ~24h after the job finishes (see `enqueueScanJob`'s retention
 * settings) — this is the permanent, full-detail record a results page actually renders, for
 * both a just-completed scan and any older one reached from a domain's trend view.
 */
export const scanReportRoutes: FastifyPluginCallbackZod = (app) => {
  app.get(
    '/scan-reports/:id',
    {
      schema: {
        tags: ['scan-reports'],
        summary: "Full results for one completed scan, by its report's permanent ID",
        params: scanReportParamsSchema,
        response: {
          200: scanReportResponseSchema,
          404: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { id } = request.params;
      const report = await getScanReportById(id);

      if (report === null) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'No scan report with that ID.',
        });
      }

      return reply.status(200).send({
        id: report.id,
        domain: report.domain.domain,
        scannedAt: report.scannedAt.toISOString(),
        overallScore: report.overallScore,
        overallGrade: report.overallGrade,
        rawResults: report.rawResults,
        computedScore: report.computedScore,
      });
    },
  );
};
