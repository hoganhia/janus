import { buildApp } from './app.js';

async function main() {
  const { app, config } = await buildApp();

  try {
    await app.listen({ port: config.PORT, host: config.HOST });
    app.log.info({ port: config.PORT }, 'Janus API listening');
  } catch (err) {
    app.log.fatal({ err }, 'Failed to start server');
    process.exit(1);
  }
}

void main();
