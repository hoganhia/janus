#!/bin/sh
set -e

cd /app/packages/db
node_modules/.bin/prisma migrate deploy
cd /app

if [ "$PROCESS_TYPE" = "worker" ]; then
  exec node packages/workers/dist/main.js
else
  exec node packages/api/dist/server.js
fi
