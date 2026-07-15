import * as Sentry from '@sentry/nextjs';

// No-op unless NEXT_PUBLIC_SENTRY_DSN is set — mirrors the API/worker's SENTRY_DSN-gated
// initSentry() (see packages/api/src/plugins/sentry.ts) so local dev with no Sentry project
// configured sends nothing anywhere. Must be NEXT_PUBLIC_-prefixed to be readable in the
// browser bundle; the DSN itself isn't a secret (it's meant to be public), that's just how
// Next.js scopes which env vars get inlined client-side.
const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;

if (dsn !== undefined) {
  Sentry.init({
    dsn,
    environment: process.env.NODE_ENV,
  });
}

export const onRouterTransitionStart = Sentry.captureRouterTransitionStart;
