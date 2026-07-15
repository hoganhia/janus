import * as Sentry from '@sentry/node';

/**
 * No-op unless SENTRY_DSN is configured. See packages/api/src/plugins/sentry.ts for the
 * matching API-side setup and the same caveat: this only captures errors, it doesn't configure
 * *alerting* on them — that's a Sentry-dashboard step, see the README.
 */
export function initSentry(dsn: string | undefined, environment: string): void {
  if (dsn === undefined) return;
  Sentry.init({ dsn, environment });
}
