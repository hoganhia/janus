import type { FastifyServerOptions } from 'fastify';

export function buildLoggerOptions(): NonNullable<FastifyServerOptions['logger']> {
  return {
    level: process.env.LOG_LEVEL ?? 'info',
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'req.body',
        'req.body.password',
        'req.body.token',
        'req.body.apiKey',
        'req.body.secret',
        'res.headers["set-cookie"]',
        'err.config.headers.authorization',
        'DATABASE_URL',
        'REDIS_URL',
        'SOME_API_KEY',
      ],
      censor: '[REDACTED]',
    },
    serializers: {
      req(request) {
        return {
          method: request.method,
          url: request.url,
          hostname: request.hostname,
          remoteAddress: request.ip,
        };
      },
    },
  };
}
