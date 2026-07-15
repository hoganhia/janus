# Janus

Passive web security scanning application. Takes a company's public URL and runs non-intrusive checks (TLS config, HTTP headers, DNS records, tech fingerprinting), then produces a scored report.

**Janus does not perform active exploitation, port scanning, or authentication bypass attempts against third-party systems.**

## Monorepo structure

| Package           | Description                       |
| ----------------- | --------------------------------- |
| `@janus/api`      | Fastify HTTP API                  |
| `@janus/scanners` | Passive security scanners         |
| `@janus/workers`  | Background job workers            |
| `@janus/shared`   | Shared types, config, Zod schemas |
| `@janus/frontend` | Web UI (scaffold)                 |

## Prerequisites

- Node.js >= 20
- pnpm >= 9

## Getting started

```bash
cp .env.example .env
pnpm install
pnpm build
pnpm dev
```

The API starts on `http://localhost:3000`.

### Endpoints

- `GET /health` — health check
- `POST /api/v1/scans` — submit a target URL for scanning (scaffold only)

## Scripts

| Command          | Description             |
| ---------------- | ----------------------- |
| `pnpm dev`       | Start API in watch mode |
| `pnpm build`     | Build all packages      |
| `pnpm typecheck` | Type-check all packages |
| `pnpm test`      | Run Vitest unit tests   |
| `pnpm lint`      | Run ESLint              |
| `pnpm format`    | Format with Prettier    |
| `pnpm audit`     | Run dependency audit    |

## Docker

```bash
docker build -t janus .
docker run -p 3000:3000 --env-file .env janus
```

## Security foundations

- Environment variables validated via Zod on startup (fail fast)
- All external input validated with Zod + Fastify schema hooks
- Pino structured logging with secret redaction
- Centralized error handler (generic external responses, detailed server-side logs)
- `@fastify/helmet` for secure headers
- `@fastify/rate-limit` middleware
- `eslint-plugin-security` in lint pipeline
- `npm audit` in CI + Dependabot for dependency updates
