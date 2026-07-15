import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().min(1).default('0.0.0.0'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_TIME_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  /** Required, no default — both the API (to enqueue scan jobs) and the scan worker (to
   * process them) need the same Redis instance. */
  REDIS_URL: z.string().min(1),
  /**
   * Identifies outbound scan requests to the *target* site being scanned (Server/X-Powered-By
   * fetches, header checks, etc.) — unrelated to any inbound client's browser User-Agent.
   * Required, with no built-in default: a placeholder value would be actively misleading if it
   * ever shipped un-customized. Should link to a page explaining what the scan is and how to
   * opt out (see ScanHeadersOptions.userAgent).
   */
  SCANNER_USER_AGENT: z.string().min(1),
  /** Required, no default — these are real secrets, and Clerk's SDK itself rejects an empty
   * secret key at plugin-registration time regardless. */
  CLERK_SECRET_KEY: z.string().min(1),
  CLERK_PUBLISHABLE_KEY: z.string().min(1),
  /**
   * Comma-separated list of exact origins allowed to make cross-origin requests to this API
   * (e.g. `https://app.example.com,https://staging.example.com`). Deliberately no wildcard
   * support and no default beyond "nothing" — an empty list means every cross-origin request is
   * rejected until this is explicitly configured, which is the safer failure mode for a tool
   * that scans arbitrary user-supplied URLs.
   */
  CORS_ALLOWED_ORIGINS: z
    .string()
    .default('')
    .transform((value) =>
      value
        .split(',')
        .map((origin) => origin.trim())
        .filter((origin) => origin.length > 0),
    ),
  /**
   * Optional — error tracking (via @sentry/node in the API/worker, @sentry/nextjs in the
   * frontend) is only enabled when this is set, so local dev with no Sentry project configured
   * doesn't send anything anywhere. Get one from a Sentry project's Settings > Client Keys page.
   */
  SENTRY_DSN: z.string().min(1).optional(),
});

export type EnvConfig = z.infer<typeof envSchema>;

export function loadConfig(): EnvConfig {
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    const formatted = result.error.flatten().fieldErrors;
    throw new Error(`Invalid environment configuration: ${JSON.stringify(formatted)}`);
  }
  return result.data;
}
