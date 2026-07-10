# ---- Build ----
FROM node:20-alpine AS builder
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/api/package.json packages/api/
COPY packages/scanners/package.json packages/scanners/
COPY packages/workers/package.json packages/workers/
COPY packages/frontend/package.json packages/frontend/

RUN pnpm install --frozen-lockfile

COPY tsconfig.base.json ./
COPY packages/ packages/

RUN pnpm --filter @janus/shared build
RUN pnpm --filter @janus/api build

# ---- Runtime ----
FROM node:20-alpine AS runtime
RUN addgroup -g 1001 -S janus && adduser -S janus -u 1001 -G janus
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --from=builder /app/packages/shared/package.json ./packages/shared/
COPY --from=builder /app/packages/api/dist ./packages/api/dist
COPY --from=builder /app/packages/api/package.json ./packages/api/
COPY --from=builder /app/package.json ./

USER janus
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "packages/api/dist/server.js"]
