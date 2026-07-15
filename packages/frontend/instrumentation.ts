import * as Sentry from '@sentry/nextjs';

/**
 * Next.js calls this once when the server process starts (see
 * https://nextjs.org/docs/app/api-reference/file-conventions/instrumentation). This app has no
 * edge runtime routes/middleware, so only the nodejs branch is wired up — see
 * sentry.server.config.ts for the actual Sentry.init call.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    await import('./sentry.server.config');
  }
}

export const onRequestError = Sentry.captureRequestError;
