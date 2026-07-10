import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { loadConfig } from '@janus/shared';
import Fastify, { type FastifyInstance } from 'fastify';
import { registerErrorHandler } from './plugins/error-handler.js';
import { buildLoggerOptions } from './plugins/logger.js';
import { healthRoutes } from './routes/health.js';
import { scanRoutes } from './routes/scans.js';

export async function buildApp(): Promise<{
  app: FastifyInstance;
  config: ReturnType<typeof loadConfig>;
}> {
  const config = loadConfig();

  const app = Fastify({
    logger: buildLoggerOptions(),
    trustProxy: true,
  });

  registerErrorHandler(app);

  await app.register(helmet, {
    contentSecurityPolicy: config.NODE_ENV === 'production',
    hsts:
      config.NODE_ENV === 'production'
        ? { maxAge: 31536000, includeSubDomains: true, preload: true }
        : false,
  });

  await app.register(rateLimit, {
    max: config.RATE_LIMIT_MAX,
    timeWindow: config.RATE_LIMIT_TIME_WINDOW_MS,
  });

  if (config.NODE_ENV === 'production') {
    app.addHook('onRequest', async (request, reply) => {
      const proto = request.headers['x-forwarded-proto'];
      if (proto && proto !== 'https') {
        return reply.status(403).send({
          error: 'Forbidden',
          message: 'HTTPS required',
        });
      }
    });
  }

  await app.register(healthRoutes);
  await app.register(scanRoutes, { prefix: '/api/v1' });

  return { app, config };
}
