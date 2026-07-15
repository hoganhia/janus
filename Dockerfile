# Single image for both Railway services (API and worker) — they share the same dependency
# graph (@janus/db, @janus/scanners, @janus/shared) and differ only in their start command,
# set per-service in Railway rather than via separate Dockerfiles/CMDs here.

# ---- Build ----
# pnpm 11 (this repo's lockfile version) requires Node >=22.13 to run its own CLI.
FROM node:22-alpine AS builder
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/db/package.json packages/db/
COPY packages/scanners/package.json packages/scanners/
COPY packages/workers/package.json packages/workers/
COPY packages/api/package.json packages/api/

# @janus/db's postinstall runs `prisma generate`, which needs the schema present at install
# time, not just at build time.
COPY packages/db/prisma packages/db/prisma
COPY packages/db/prisma.config.ts packages/db/

RUN pnpm install --frozen-lockfile

COPY tsconfig.base.json ./
COPY packages/shared/ packages/shared/
COPY packages/db/ packages/db/
COPY packages/scanners/ packages/scanners/
COPY packages/workers/ packages/workers/
COPY packages/api/ packages/api/

RUN pnpm --filter @janus/shared build
RUN pnpm --filter @janus/db build
RUN pnpm --filter @janus/scanners build
RUN pnpm --filter @janus/workers build
RUN pnpm --filter @janus/api build

# ---- Runtime ----
FROM node:22-alpine AS runtime
RUN addgroup -g 1001 -S janus && adduser -S janus -u 1001 -G janus
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --from=builder /app/packages/shared/package.json ./packages/shared/

COPY --from=builder /app/packages/db/dist ./packages/db/dist
COPY --from=builder /app/packages/db/package.json ./packages/db/
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma
COPY --from=builder /app/packages/db/prisma.config.ts ./packages/db/

COPY --from=builder /app/packages/scanners/dist ./packages/scanners/dist
COPY --from=builder /app/packages/scanners/package.json ./packages/scanners/

COPY --from=builder /app/packages/workers/dist ./packages/workers/dist
COPY --from=builder /app/packages/workers/package.json ./packages/workers/

COPY --from=builder /app/packages/api/dist ./packages/api/dist
COPY --from=builder /app/packages/api/package.json ./packages/api/

# pnpm links each package's own dependencies (workspace packages like @janus/shared, and
# regular deps like zod/pino/undici) into that package's own node_modules, not just the root
# node_modules — copy all of them so imports resolve at runtime.
COPY --from=builder /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=builder /app/packages/db/node_modules ./packages/db/node_modules
COPY --from=builder /app/packages/scanners/node_modules ./packages/scanners/node_modules
COPY --from=builder /app/packages/workers/node_modules ./packages/workers/node_modules
COPY --from=builder /app/packages/api/node_modules ./packages/api/node_modules

COPY scripts/docker-entrypoint.sh /app/docker-entrypoint.sh

USER janus
ENV NODE_ENV=production
EXPOSE 3000

# Runs `prisma migrate deploy` then starts the API by default, or the worker if
# PROCESS_TYPE=worker is set — lets one image serve both Railway services (set via each
# service's own env vars) without needing a per-service custom start command.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
