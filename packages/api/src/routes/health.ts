import type { FastifyInstance } from 'fastify';

export function healthRoutes(app: FastifyInstance): void {
  app.get(
    '/health',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              status: { type: 'string' },
              timestamp: { type: 'string' },
            },
            required: ['status', 'timestamp'],
          },
        },
      },
    },
    () => ({
      status: 'ok',
      timestamp: new Date().toISOString(),
    }),
  );
}
