import dns from 'node:dns';

/**
 * `dns.promises` has no built-in per-query timeout, and its own internal retry/timeout
 * behavior can take much longer than we want to wait for a single scan check. `Resolver.cancel()`
 * reliably aborts an outstanding query (verified directly: pointing a resolver at a
 * non-responding address and calling `cancel()` after a fixed delay rejects the pending call
 * immediately with `ECANCELLED`, rather than waiting out Node's own retry schedule).
 */
const DEFAULT_TIMEOUT_MS = 5000;

export type DnsLookupNotFoundCode = 'NXDOMAIN' | 'NO_DATA';
export type DnsLookupErrorCode = 'TIMEOUT' | 'OTHER';

export type DnsLookupResult<T> =
  | { status: 'found'; records: T }
  | { status: 'not-found'; code: DnsLookupNotFoundCode }
  | { status: 'error'; code: DnsLookupErrorCode; message: string };

function classifyFailure(
  err: unknown,
):
  { kind: 'not-found'; code: DnsLookupNotFoundCode } | { kind: 'error'; code: DnsLookupErrorCode } {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code === 'ENOTFOUND') return { kind: 'not-found', code: 'NXDOMAIN' };
  if (code === 'ENODATA') return { kind: 'not-found', code: 'NO_DATA' };
  if (code === 'ECANCELLED' || code === 'ETIMEOUT') return { kind: 'error', code: 'TIMEOUT' };
  return { kind: 'error', code: 'OTHER' };
}

export interface DnsLookupOptions {
  timeoutMs?: number;
  /** Overrides the resolver's nameservers — mainly for tests that need a deterministic,
   * non-responding target to exercise the timeout path. */
  servers?: string[];
}

async function withTimeout<T>(
  run: (resolver: dns.promises.Resolver) => Promise<T>,
  options: DnsLookupOptions,
): Promise<T> {
  const resolver = new dns.promises.Resolver();
  if (options.servers !== undefined) resolver.setServers(options.servers);
  const timer = setTimeout(() => {
    resolver.cancel();
  }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    return await run(resolver);
  } finally {
    clearTimeout(timer);
  }
}

async function lookup<T>(
  run: (resolver: dns.promises.Resolver) => Promise<T>,
  options: DnsLookupOptions,
): Promise<DnsLookupResult<T>> {
  try {
    const records = await withTimeout(run, options);
    return { status: 'found', records };
  } catch (err) {
    const failure = classifyFailure(err);
    if (failure.kind === 'not-found') return { status: 'not-found', code: failure.code };
    return {
      status: 'error',
      code: failure.code,
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

/** Each TXT record is returned as `string[]` — DNS splits long values into multiple chunks
 * that represent a single logical string when concatenated. */
export function lookupTxt(
  name: string,
  options: DnsLookupOptions = {},
): Promise<DnsLookupResult<string[][]>> {
  return lookup((resolver) => resolver.resolveTxt(name), options);
}

export function lookupMx(
  name: string,
  options: DnsLookupOptions = {},
): Promise<DnsLookupResult<dns.MxRecord[]>> {
  return lookup((resolver) => resolver.resolveMx(name), options);
}

/** Joins the chunks of a single TXT record into the logical string it represents. */
export function joinTxtRecord(chunks: string[]): string {
  return chunks.join('');
}
