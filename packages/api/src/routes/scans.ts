import { enqueueScanJob, type ScanJobData, type ScanQueueLike } from '@janus/workers';
import { ScanTargetRejectedError, targetUrlSchema, validateScanTarget } from '@janus/shared';
import type { FastifyPluginCallbackZod } from 'fastify-type-provider-zod';
// See the comment in ../schemas.ts on why this is 'zod/v4' rather than the classic 'zod' import.
// `targetUrlSchema` above is a classic-v3 schema (built in @janus/shared, which the rest of the
// monorepo depends on) — nesting a v3 schema instance as a *field* inside a v4 z.object() is
// NOT compatible: verified directly, it throws "expected a Zod schema" at runtime (zod/v4's
// object() does a real prototype check, not just a structural one TS would be satisfied by).
// So the route schema below only checks `targetUrl` is a non-empty string; the real format/
// SSRF-adjacent checks still go through the actual `targetUrlSchema.safeParse()` call in the
// handler, exactly reusing the Prompt-0 schema, just via a function call instead of nesting.
import { z } from 'zod/v4';
import { errorResponseSchema } from '../schemas.js';

export interface ScanRoutesOptions {
  scanQueue: ScanQueueLike;
  /** Sent as the User-Agent on every outbound scan request — see SCANNER_USER_AGENT. */
  scannerUserAgent: string;
}

/**
 * Scan submission is anonymous by design (POC decision) — matching common tools in this space
 * (SSL Labs, Mozilla Observatory): no account is required to check a site's own public-facing
 * posture. The per-IP submission limit below is the primary abuse guard; see
 * `ScanWorkerOptions.rateLimitMax` in `@janus/workers` for the (global, not per-IP) worker-side
 * throughput cap that backs it up. Login is still required for the account-tied actions in
 * `domain-verification.ts` (claiming/verifying a domain), which is a materially different kind
 * of action than "check a public URL."
 */
const IP_RATE_LIMIT_MAX = 5;
const IP_RATE_LIMIT_TIME_WINDOW_MS = 60 * 60 * 1000;

const createScanBodySchema = z.object({
  targetUrl: z.string().min(1),
});

const createScanResponseSchema = z.object({
  jobId: z.string(),
  targetUrl: z.string(),
});

const scanStatusParamsSchema = z.object({
  id: z.string().min(1),
});

const letterGradeSchema = z.enum(['A', 'B', 'C', 'D', 'F']);

const scanJobResultSchema = z.object({
  domain: z.string(),
  scanReportId: z.string(),
  overallScore: z.number(),
  overallGrade: letterGradeSchema,
});

const scanStatusResponseSchema = z.object({
  jobId: z.string(),
  status: z.string(),
  result: scanJobResultSchema.optional(),
  failedReason: z.string().optional(),
});

export const scanRoutes: FastifyPluginCallbackZod<ScanRoutesOptions> = (app, options) => {
  app.post(
    '/scans',
    {
      config: {
        rateLimit: {
          max: IP_RATE_LIMIT_MAX,
          timeWindow: IP_RATE_LIMIT_TIME_WINDOW_MS,
        },
      },
      schema: {
        tags: ['scans'],
        summary: 'Submit a URL for an asynchronous passive security scan',
        body: createScanBodySchema,
        response: {
          202: createScanResponseSchema,
          400: errorResponseSchema,
          429: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      // The route schema above only checks `targetUrl` is a non-empty string (see the import
      // comment for why the real schema can't be nested there); this is the actual format check
      // — URL shape, http(s)-only, no credentials, not already a private/reserved IP literal —
      // reusing the exact Prompt-0 schema from @janus/shared.
      const parsed = targetUrlSchema.safeParse(request.body.targetUrl);
      if (!parsed.success) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Target must be a scannable public URL',
        });
      }
      const targetUrl = parsed.data;

      // The single SSRF/rebinding gate every scanner is built on — see @janus/shared. A target
      // that fails here would fail identically for every scanner, so there's no point queueing
      // it; the worker re-runs this same check right before scanning regardless (see
      // packages/workers/src/scan-job/run-scan.ts), since enough time may have passed by then
      // for DNS to have been rebound out from under this check.
      try {
        await validateScanTarget(targetUrl, {
          requesterIp: request.ip,
          userAgent: options.scannerUserAgent,
        });
      } catch (err) {
        if (err instanceof ScanTargetRejectedError) {
          return reply.status(400).send({
            error: 'Bad Request',
            message: 'Target must be a scannable public URL',
          });
        }
        throw err;
      }

      const jobData: ScanJobData = {
        targetUrl,
        requesterIp: request.ip,
        userAgent: options.scannerUserAgent,
      };
      const job = await enqueueScanJob(options.scanQueue, jobData);
      // enqueueScanJob always passes an explicit jobId when adding the job, so this is never
      // actually undefined at runtime — BullMQ's own `Job.id` type just doesn't reflect that.
      const jobId = job.id;
      if (jobId === undefined) {
        throw new Error('Enqueued scan job has no ID');
      }

      request.log.info({ jobId, targetUrl }, 'Scan job enqueued');

      return reply.status(202).send({ jobId, targetUrl });
    },
  );

  app.get(
    '/scans/:id',
    {
      schema: {
        tags: ['scans'],
        summary: 'Check the status of a scan, and its results once complete',
        params: scanStatusParamsSchema,
        response: {
          200: scanStatusResponseSchema,
          404: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { id } = request.params;

      // `id` is a random (crypto) UUID assigned at enqueue time, not a guessable sequential
      // value — see enqueueScanJob's own doc comment — so "no ownership check" here is a
      // deliberate consequence of scan submission being anonymous, not an oversight: there's no
      // account to check ownership against, and the ID itself is the access control.
      const job = await options.scanQueue.getJob(id);
      if (job === undefined) {
        return reply.status(404).send({
          error: 'Not Found',
          message: 'No scan job with that ID.',
        });
      }

      const status = await job.getState();

      if (status === 'completed') {
        return reply.status(200).send({ jobId: id, status, result: job.returnvalue });
      }
      if (status === 'failed') {
        return reply.status(200).send({ jobId: id, status, failedReason: job.failedReason });
      }
      return reply.status(200).send({ jobId: id, status });
    },
  );
};
