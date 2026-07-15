import type { NextConfig } from 'next';
import { withSentryConfig } from '@sentry/nextjs';

const nextConfig: NextConfig = {
  // Every scan result string (header values, TLS cert fields, DNS record content) comes from a
  // target the caller chose, not from us — see lib/api.ts and the components under app/reports.
  // Nothing here ever needs to render trusted HTML from that data, so there is deliberately no
  // dangerouslyAllowSVG/rewrites/etc. configuration that would widen that surface.
};

// Wraps the config with Sentry's build-time behavior (source-map upload, instrumentation
// hookup) regardless of whether SENTRY_DSN is actually set — see instrumentation-client.ts and
// sentry.server.config.ts for the runtime no-op-without-a-DSN gate. Without org/project/
// authToken configured, the plugin just skips the source-map-upload step (with a build-time
// warning), it doesn't fail the build — safe to leave wrapped even before a real Sentry project
// exists.
export default withSentryConfig(nextConfig, {
  org: process.env.SENTRY_ORG,
  project: process.env.SENTRY_PROJECT,
  silent: true,
});
