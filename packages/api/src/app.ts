import { clerkPlugin } from '@clerk/fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';
import { loadConfig } from '@janus/shared';
import { createScanQueue } from '@janus/workers';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  jsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { registerErrorHandler } from './plugins/error-handler.js';
import { buildLoggerOptions } from './plugins/logger.js';
import { abuseReportRoutes } from './routes/abuse-report.js';
import { domainVerificationRoutes } from './routes/domain-verification.js';
import { domainRoutes } from './routes/domains.js';
import { healthRoutes } from './routes/health.js';
import { scanReportRoutes } from './routes/scan-reports.js';
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

  // Explicit allow-list only, no wildcard — an empty list (the default) means every
  // cross-origin request is rejected until CORS_ALLOWED_ORIGINS is configured.
  await app.register(cors, {
    origin: config.CORS_ALLOWED_ORIGINS.length > 0 ? config.CORS_ALLOWED_ORIGINS : false,
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

  await app.register(fastifySwagger, {
    openapi: {
      info: {
        title: 'Janus Security Scanner API',
        description:
          'Passive external security scanning: TLS configuration, HTTP response headers, DNS/email authentication, and software fingerprinting. Every scan report includes an explicit disclaimer — this is not a SOC 2, PCI DSS, or other compliance certification.',
        version: '1.0.0',
      },
    },
    transform: jsonSchemaTransform,
  });
  await app.register(fastifySwaggerUi, {
    routePrefix: '/docs',
  });

  // Applies to every route registered from here on — see packages/api/src/routes/*.ts, all of
  // which declare zod schemas (reusing @janus/shared's schemas where relevant, e.g.
  // targetUrlSchema) rather than hand-written JSON schema.
  app.setValidatorCompiler(validatorCompiler);
  // fastify-type-provider-zod's serializerCompiler type doesn't fully resolve against this
  // Fastify version's FastifySerializerCompiler generic (a known type-friction spot between the
  // two packages' zod-core/Fastify type versions) — the runtime behavior is unaffected, this
  // only silences the resulting `any`-typed-argument lint warning.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  app.setSerializerCompiler(serializerCompiler);

  const scanQueue = createScanQueue({ redisUrl: config.REDIS_URL });
  app.addHook('onClose', async () => {
    await scanQueue.close();
  });

  await app.register(healthRoutes);

  // scanRoutes needs no Clerk dependency at all — scan submission is anonymous by design (see
  // scans.ts) — so it's registered directly here, alongside the other public routes, rather
  // than inside the Clerk-scoped block below. This matters beyond tidiness: it's what keeps a
  // Clerk misconfiguration from being able to take down the app's core always-on feature, the
  // same reasoning that already applies to /health and /domains/:domain/history. Verified
  // directly earlier: with the placeholder Clerk keys this scaffold ships (see .env), a global
  // clerkPlugin registration made every route under it fail with a 500 from Clerk's own
  // key-format validation — scanning must not be able to fail that way.
  await app.register(scanRoutes, {
    prefix: '/api/v1',
    scanQueue,
    scannerUserAgent: config.SCANNER_USER_AGENT,
  });

  // clerkPlugin is scoped to just the routes that actually call `getAuth` (via `requireAuth`,
  // see plugins/auth.ts) — domain verification's start/check endpoints are still account-tied
  // (claiming a domain is a materially different action than checking a public URL).
  await app.register(
    async (scoped) => {
      await scoped.register(clerkPlugin, {
        secretKey: config.CLERK_SECRET_KEY,
        publishableKey: config.CLERK_PUBLISHABLE_KEY,
        hookName: 'preHandler',
      });
      await scoped.register(domainVerificationRoutes, {
        scannerUserAgent: config.SCANNER_USER_AGENT,
      });
    },
    { prefix: '/api/v1' },
  );

  await app.register(domainRoutes, { prefix: '/api/v1' });
  await app.register(scanReportRoutes, { prefix: '/api/v1' });
  await app.register(abuseReportRoutes, { prefix: '/api/v1' });

  return { app, config };
}
