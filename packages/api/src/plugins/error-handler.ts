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

    return reply.status(statusCode).send({
      error: isServerError ? 'Internal Server Error' : 'Request Error',
      message: isServerError ? 'An unexpected error occurred' : 'Request could not be processed',
    });
  });
}
