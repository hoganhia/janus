import { createAbuseReport } from '@janus/db';
import type { FastifyPluginCallbackZod } from 'fastify-type-provider-zod';
// See the comment in ../schemas.ts on why this is 'zod/v4' rather than the classic 'zod' import.
import { z } from 'zod/v4';
import { domainNameSchema, errorResponseSchema } from '../schemas.js';

// A far lower ceiling than the scan-submission limit (see scans.ts's IP_RATE_LIMIT_MAX) — this
// route does no outbound scanning at all, so the only thing it needs to bound is complaint spam.
const IP_RATE_LIMIT_MAX = 10;
const IP_RATE_LIMIT_TIME_WINDOW_MS = 60 * 60 * 1000;

const abuseReportBodySchema = z.object({
  domain: domainNameSchema,
  reason: z.string().min(1).max(500),
  details: z.string().max(2000).optional(),
  /** Free-text, not validated as a real email — optional, only used if the reporter wants a reply. */
  contact: z.string().max(320).optional(),
});

const abuseReportResponseSchema = z.object({
  id: z.string(),
});

/**
 * Public, unauthenticated by design — same reasoning as scan submission (see scans.ts): someone
 * reporting a problem with this scanner shouldn't need an account to do it. Complements the
 * self-service `_perimeter-opt-out` DNS TXT record (see check-opt-out.ts): that record stops
 * *future* scans immediately without any human involvement, while this is a manual-review
 * channel for anyone who can't add DNS records, wants to flag a problem retroactively, or has a
 * concern that isn't just "stop scanning me" (e.g. request volume, a specific bad interaction).
 * Every submission is logged at `warn` so it surfaces in whatever log/alerting pipeline is
 * watching for anomalies — see the Sentry wiring in server.ts for how "unusual failure rate"
 * alerting is set up.
 */
export const abuseReportRoutes: FastifyPluginCallbackZod = (app) => {
  app.post(
    '/abuse-report',
    {
      config: {
        rateLimit: {
          max: IP_RATE_LIMIT_MAX,
          timeWindow: IP_RATE_LIMIT_TIME_WINDOW_MS,
        },
      },
      schema: {
        tags: ['abuse-report'],
        summary: 'Report a concern about this scanner’s behavior toward a domain',
        body: abuseReportBodySchema,
        response: {
          201: abuseReportResponseSchema,
          400: errorResponseSchema,
          429: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { domain, reason, details, contact } = request.body;

      const report = await createAbuseReport({
        domain,
        reason,
        ...(details !== undefined ? { details } : {}),
        ...(contact !== undefined ? { contact } : {}),
      });

      request.log.warn({ abuseReportId: report.id, domain, reason }, 'Abuse report submitted');

      return reply.status(201).send({ id: report.id });
    },
  );
};
