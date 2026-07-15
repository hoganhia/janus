/**
 * The fixed, small set of products `fingerprintStack` can passively detect and the CVE sync
 * job pulls data for. A product's *display* name (what a Server/X-Powered-By header shows)
 * often differs from its CPE vendor:product identity in NVD's dictionary — these were checked
 * directly against the live NVD API before being hardcoded here, not guessed:
 *   - nginx's CPE vendor is "f5", not "nginx" (F5 acquired NGINX Inc.)
 *   - WordPress *core* is cpe:2.3:a:wordpress:wordpress — WordPress *plugin* CVEs (a large,
 *     noisy set) use unrelated vendor:product pairs with wordpress only as target_sw, which is
 *     exactly why this catalog exists instead of a plain keyword search at query time.
 *   - IIS's CPE product is "internet_information_server" (NVD's legacy naming), not "..._services".
 *   - Next.js predates Vercel's rebrand from "Zeit" and still uses that CPE vendor.
 * Express, LiteSpeed, OpenResty, and Caddy use their conventional/well-documented NVD CPE
 * identifiers but weren't individually re-verified against a live query — low-risk to fix
 * later since this is a flat, one-row-per-product table.
 */
export interface ProductCatalogEntry {
  /** Our own stable key — stored on CveAffectedProduct rows, matched against detector output. */
  key: string;
  /** Human-readable name for report text. */
  displayName: string;
  cpeVendor: string;
  cpeProduct: string;
  /** Passed to NVD's `keywordSearch` to narrow candidates before CPE-filtering the results. */
  nvdKeyword: string;
}

export const PRODUCT_CATALOG: readonly ProductCatalogEntry[] = [
  { key: 'nginx', displayName: 'nginx', cpeVendor: 'f5', cpeProduct: 'nginx', nvdKeyword: 'nginx' },
  {
    key: 'apache-httpd',
    displayName: 'Apache HTTP Server',
    cpeVendor: 'apache',
    cpeProduct: 'http_server',
    nvdKeyword: 'Apache HTTP Server',
  },
  {
    key: 'iis',
    displayName: 'Microsoft IIS',
    cpeVendor: 'microsoft',
    cpeProduct: 'internet_information_server',
    nvdKeyword: 'Internet Information Services',
  },
  { key: 'php', displayName: 'PHP', cpeVendor: 'php', cpeProduct: 'php', nvdKeyword: 'PHP' },
  {
    key: 'wordpress',
    displayName: 'WordPress',
    cpeVendor: 'wordpress',
    cpeProduct: 'wordpress',
    nvdKeyword: 'WordPress',
  },
  {
    key: 'nextjs',
    displayName: 'Next.js',
    cpeVendor: 'zeit',
    cpeProduct: 'next.js',
    nvdKeyword: 'Next.js',
  },
  {
    key: 'express',
    displayName: 'Express',
    cpeVendor: 'expressjs',
    cpeProduct: 'express',
    nvdKeyword: 'Express.js',
  },
  {
    key: 'litespeed',
    displayName: 'LiteSpeed Web Server',
    cpeVendor: 'litespeedtech',
    cpeProduct: 'litespeed_web_server',
    nvdKeyword: 'LiteSpeed Web Server',
  },
  {
    key: 'openresty',
    displayName: 'OpenResty',
    cpeVendor: 'openresty',
    cpeProduct: 'openresty',
    nvdKeyword: 'OpenResty',
  },
  {
    key: 'caddy',
    displayName: 'Caddy',
    cpeVendor: 'caddyserver',
    cpeProduct: 'caddy',
    nvdKeyword: 'Caddy web server',
  },
] as const;

export function findProductByKey(key: string): ProductCatalogEntry | undefined {
  return PRODUCT_CATALOG.find((p) => p.key === key);
}
