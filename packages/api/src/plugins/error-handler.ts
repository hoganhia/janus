import * as Sentry from '@sentry/node';
import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodError } from 'zod';

export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((error: FastifyError, request: FastifyRequest, reply: FastifyReply) => {
    request.log.error({ err: error }, 'Request failed');

    if (error.validation) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Invalid request',
      });
    }

    if (error instanceof ZodError) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Invalid request',
      });
    }

    const statusCode = error.statusCode ?? 500;
    const isServerError = statusCode >= 500;

    // Only genuine server errors, not expected 4xx rejections (bad input, rate limits) — those
    // would otherwise dominate Sentry's issue/error-rate signal and bury real crashes.
    if (isServerError) {
      Sentry.captureException(error, {
        extra: { method: request.method, url: request.url },
      });
    }

    return reply.status(statusCode).send({
      error: isServerError ? 'Internal Server Error' : 'Request Error',
      message: isServerError ? 'An unexpected error occurred' : 'Request could not be processed',
    });
  });
}
