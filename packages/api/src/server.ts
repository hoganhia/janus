import { loadConfig } from '@janus/shared';
import * as Sentry from '@sentry/node';
import { buildApp } from './app.js';
import { initSentry } from './plugins/sentry.js';

async function main() {
  // Initialized before buildApp() so Sentry's instrumentation (unhandled rejection/exception
  // capture, HTTP tracing) is active for the whole process lifetime — see plugins/sentry.ts.
  const earlyConfig = loadConfig();
  initSentry(earlyConfig.SENTRY_DSN, earlyConfig.NODE_ENV);

  const { app, config } = await buildApp();

  try {
    await app.listen({ port: config.PORT, host: config.HOST });
    app.log.info({ port: config.PORT }, 'Janus API listening');
  } catch (err) {
    app.log.fatal({ err }, 'Failed to start server');
    Sentry.captureException(err);
    await Sentry.flush(2000);
    process.exit(1);
  }
}

void main();
