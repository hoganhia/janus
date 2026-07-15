import * as Sentry from '@sentry/nextjs';

// Server-only — SENTRY_DSN (no NEXT_PUBLIC_ prefix) is never bundled into client code. See
// instrumentation-client.ts for the browser-side counterpart and instrumentation.ts for where
// this file is loaded from.
const dsn = process.env.SENTRY_DSN;

if (dsn !== undefined) {
  Sentry.init({
    dsn,
    environment: process.env.NODE_ENV,
  });
}
