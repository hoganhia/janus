import Redis from 'ioredis';

// Railway's Redis is cross-provider from Vercel's functions, so a cold first connection can
// take a while — ioredis's own default connectTimeout (10s) would make a visitor wait that
// long before this fails open. Kept short so a slow/cold connection degrades to "no rate
// limiting this request" quickly rather than stalling the login form.
const CONNECT_TIMEOUT_MS = 1500;
const COMMAND_TIMEOUT_MS = 1500;

let client: Redis | undefined;

function getClient(): Redis | undefined {
  const url = process.env.REDIS_URL;
  if (url === undefined || url === '') return undefined;
  client ??= new Redis(url, {
    maxRetriesPerRequest: 1,
    lazyConnect: true,
    connectTimeout: CONNECT_TIMEOUT_MS,
    commandTimeout: COMMAND_TIMEOUT_MS,
  });
  return client;
}

/**
 * Fixed-window rate limiter backed by Redis (shared across serverless instances — an
 * in-memory counter would not survive across Vercel's ephemeral function invocations).
 * Fails open (allows the request) if Redis is unreachable, slow, or REDIS_URL is unset — the
 * same fail-open convention used by the DNS opt-out check in @janus/shared, since a backend
 * hiccup here must not itself lock every visitor out.
 */
export async function checkRateLimit(
  key: string,
  maxAttempts: number,
  windowSeconds: number,
): Promise<{ allowed: boolean }> {
  const redis = getClient();
  if (redis === undefined) return { allowed: true };

  try {
    const count = await redis.incr(key);
    if (count === 1) {
      await redis.expire(key, windowSeconds);
    }
    return { allowed: count <= maxAttempts };
  } catch {
    return { allowed: true };
  }
}
