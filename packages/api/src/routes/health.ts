import type { FastifyPluginCallbackZod } from 'fastify-type-provider-zod';
// See the comment in ../schemas.ts on why this is 'zod/v4' rather than the classic 'zod' import.
import { z } from 'zod/v4';

const healthResponseSchema = z.object({
  status: z.string(),
  timestamp: z.string(),
});

export const healthRoutes: FastifyPluginCallbackZod = (app) => {
  app.get(
    '/health',
    {
      schema: {
        tags: ['health'],
        response: {
          200: healthResponseSchema,
        },
      },
    },
    () => ({
      status: 'ok',
      timestamp: new Date().toISOString(),
    }),
  );
};
