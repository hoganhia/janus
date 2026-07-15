/**
 * Persistence-agnostic allow/deny list for scan targets. `validateScanTarget` depends only on
 * this interface, so a Prisma-backed (or any other) store can replace `InMemoryScanTargetListStore`
 * later without touching validation logic.
 */
export interface ScanTargetListStore {
  isDenied(hostname: string): Promise<boolean>;
  isAllowed(hostname: string): Promise<boolean>;
}

function matchesHostOrSubdomain(hostname: string, entry: string): boolean {
  return hostname === entry || hostname.endsWith(`.${entry}`);
}

export interface InMemoryScanTargetListStoreOptions {
  /** Hostnames (and their subdomains) that are always rejected. */
  denied?: readonly string[];
  /** If non-empty, only these hostnames (and their subdomains) may be scanned. */
  allowed?: readonly string[];
}

/**
 * In-memory placeholder store. An empty allow-list means "no allow-list configured" — every
 * non-denied host passes. A non-empty allow-list switches to allow-list-only mode.
 */
export class InMemoryScanTargetListStore implements ScanTargetListStore {
  private readonly denied: string[];
  private readonly allowed: string[];

  constructor(options: InMemoryScanTargetListStoreOptions = {}) {
    this.denied = (options.denied ?? []).map((h) => h.toLowerCase());
    this.allowed = (options.allowed ?? []).map((h) => h.toLowerCase());
  }

  isDenied(hostname: string): Promise<boolean> {
    const host = hostname.toLowerCase();
    return Promise.resolve(this.denied.some((entry) => matchesHostOrSubdomain(host, entry)));
  }

  isAllowed(hostname: string): Promise<boolean> {
    if (this.allowed.length === 0) return Promise.resolve(true);
    const host = hostname.toLowerCase();
    return Promise.resolve(this.allowed.some((entry) => matchesHostOrSubdomain(host, entry)));
  }
}
