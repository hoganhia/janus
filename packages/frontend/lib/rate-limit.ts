import Redis from 'ioredis';

let client: Redis | undefined;

function getClient(): Redis | undefined {
  const url = process.env.REDIS_URL;
  if (url === undefined || url === '') return undefined;
  client ??= new Redis(url, { maxRetriesPerRequest: 1, lazyConnect: true });
  return client;
}

/**
 * Fixed-window rate limiter backed by Redis (shared across serverless instances — an
 * in-memory counter would not survive across Vercel's ephemeral function invocations).
 * Fails open (allows the request) if Redis is unreachable or REDIS_URL is unset — the same
 * fail-open convention used by the DNS opt-out check in @janus/shared, since a backend hiccup
 * here must not itself lock every visitor out.
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
