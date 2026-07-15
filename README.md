# Janus

[![CI](https://github.com/hoganhia/janus/actions/workflows/ci.yml/badge.svg)](https://github.com/hoganhia/janus/actions/workflows/ci.yml)

Passive web security scanning application. Takes a company's public URL and runs non-intrusive checks (TLS config, HTTP headers, DNS records, tech fingerprinting), then produces a scored report with concrete remediation suggestions for anything that fails.

**Janus does not perform active exploitation, port scanning, or authentication bypass attempts against third-party systems.**

**Live demo:** [janusscan.vercel.app](https://janusscan.vercel.app) — password-protected, ask for access.

## Tech stack

Fastify API + BullMQ background workers + Next.js 16 (App Router) frontend, Postgres (Prisma) +
Redis, TypeScript throughout, Zod for runtime validation end to end. Deployed as a Docker image
on Railway (API + worker + Postgres + Redis) and Next.js on Vercel. CVE data is synced from the
real NVD (National Vulnerability Database) API on a schedule, not bundled/mocked.

## Monorepo structure

| Package           | Description                                                                                                                    |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `@janus/api`      | Fastify HTTP API                                                                                                               |
| `@janus/scanners` | Passive security scanners                                                                                                      |
| `@janus/workers`  | Background job workers                                                                                                         |
| `@janus/shared`   | Shared types, config, Zod schemas                                                                                              |
| `@janus/db`       | Prisma/Postgres persistence, used by the API and workers                                                                       |
| `@janus/frontend` | Next.js web UI — landing page, scan-progress polling, results, domain history trends, methodology and about-this-scanner pages |

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
- `POST /api/v1/scans` — submit a target URL for an asynchronous passive scan
- `GET /api/v1/scans/:id` — check a scan job's status, and its result once complete
- `GET /api/v1/scan-reports/:id` — full results for a completed scan, by its permanent report ID
- `GET /api/v1/domains/:domain/history` — a domain's past scan history
- `GET /api/v1/domains/:domain/verification` — a domain's current ownership-verification status and scan tier
- `POST /api/v1/domains/:domain/verification` — start a domain-ownership verification challenge (auth required)
- `POST /api/v1/domains/:domain/verification/check` — check a pending domain-ownership verification challenge (auth required)
- `POST /api/v1/abuse-report` — report a concern about this scanner's behavior toward a domain

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
- Self-service DNS opt-out (`_janus-opt-out.<domain> TXT "true"`) honored on every scan
  target and hop, unless the domain has a verified owner — see
  `packages/shared/src/scan-target/check-opt-out.ts`
- `POST /api/v1/abuse-report` — a manual-review channel for anyone who can't add the DNS
  record above or has a different concern about scan traffic

## Error tracking & alerting

`@sentry/node` (API, worker) and `@sentry/nextjs` (frontend) are wired in but no-op until a
DSN is configured — see `SENTRY_DSN` / `NEXT_PUBLIC_SENTRY_DSN` in `.env.example`. What's
captured automatically once a DSN is set:

- Unhandled exceptions/rejections in every process (Sentry's default instrumentation)
- Every 5xx from the API's Fastify error handler (`packages/api/src/plugins/error-handler.ts`)
- A scan job's _final_ failed attempt (not each retry — see `packages/workers/src/main.ts`)
- Frontend rendering/navigation errors (`instrumentation.ts` / `instrumentation-client.ts`)

**Capturing errors is not the same as alerting on them** — that's configured in the Sentry
dashboard, not this codebase, once a project/DSN exists:

1. **Project Settings > Alerts > Create Alert Rule** — an Issue Alert firing on "A new issue is
   created" covers the "get notified of crashes" half of this.
2. For "unusual failure rate spikes," use a **Metric Alert** on the `failure_rate()` or
   `count()` metric, scoped to this project, with a threshold/time-window that fits your actual
   traffic (there's no one-size-fits-all default — start conservative and tighten once you know
   the real baseline error rate).
3. Point both at whatever notification channel you want paged on (email, Slack, PagerDuty,
   etc.) under **Alerts > \[rule\] > Notify**.
