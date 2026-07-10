import { resolvePublicAddress, targetUrlSchema, UnsafeScanTargetError } from '@janus/shared';
import type { FastifyInstance } from 'fastify';

export function scanRoutes(app: FastifyInstance): void {
  app.post(
    '/scans',
    {
      schema: {
        body: {
          type: 'object',
          required: ['targetUrl'],
          properties: {
            targetUrl: { type: 'string', format: 'uri' },
          },
          additionalProperties: false,
        },
        response: {
          202: {
            type: 'object',
            properties: {
              message: { type: 'string' },
              targetUrl: { type: 'string' },
            },
          },
          400: {
            type: 'object',
            properties: {
              error: { type: 'string' },
              message: { type: 'string' },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const { targetUrl } = request.body as { targetUrl: string };

      const parsed = targetUrlSchema.safeParse(targetUrl);
      if (!parsed.success) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: 'Invalid request',
        });
      }

      // Re-check against the address actually resolved right now, not just the hostname
      // string — closes the DNS-rebinding gap the schema-level check can't cover. Whatever
      // scanner eventually performs the fetch must reuse this pinned address rather than
      // re-resolving the hostname.
      try {
        await resolvePublicAddress(new URL(parsed.data).hostname);
      } catch (err) {
        if (err instanceof UnsafeScanTargetError) {
          return reply.status(400).send({
            error: 'Bad Request',
            message: 'Target must be a public URL',
          });
        }
        throw err;
      }

      request.log.info({ targetUrl: parsed.data }, 'Scan requested (not implemented)');

      return reply.status(202).send({
        message: 'Scan queued (scaffold only)',
        targetUrl: parsed.data,
      });
    },
  );
}
