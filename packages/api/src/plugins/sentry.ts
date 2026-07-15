import * as Sentry from '@sentry/node';

/**
 * No-op unless SENTRY_DSN is configured — local dev with no Sentry project set up sends
 * nothing anywhere. Must run before `buildApp()`/`app.listen()` so Sentry's instrumentation
 * (unhandled rejection/exception capture, HTTP request tracing) is active for the whole
 * process lifetime, not just requests handled after some later point.
 *
 * Capturing errors here is necessary but not sufficient for "get notified of crashes or
 * unusual failure rate spikes" (see Prompt 8) — that alerting itself is configured in the
 * Sentry dashboard (Project Settings > Alerts), not in this codebase; see the README for the
 * specific rules to set up once a project/DSN exists.
 */
export function initSentry(dsn: string | undefined, environment: string): void {
  if (dsn === undefined) return;
  Sentry.init({ dsn, environment });
}
