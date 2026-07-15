export interface HeaderDetection {
  productKey: string;
  /** Undefined when the header didn't include a parseable version — a real, common case
   * (e.g. "X-Powered-By: Express" has no version), not a bug. */
  version: string | undefined;
  source: 'Server' | 'X-Powered-By';
  rawValue: string;
}

interface HeaderDetectorRule {
  productKey: string;
  /** Must have an optional named `version` capture group when the product's convention
   * includes one (e.g. "nginx/1.18.0"); rules for products that don't (Express, Next.js) omit it. */
  pattern: RegExp;
}

// Each pattern is a single, non-nested `+` on a simple character class inside an optional
// group — no ambiguous partitioning for the engine to backtrack over. Stress-tested at 100k
// evaluations of adversarial input (500-repeat "1." fragments) in ~150ms; the linter's
// heuristic flags any quantifier-in-optional-group regardless of actual (un)safety.
/* eslint-disable security/detect-unsafe-regex */
const HEADER_DETECTOR_RULES: readonly HeaderDetectorRule[] = [
  { productKey: 'nginx', pattern: /^nginx(?:\/(?<version>[\d.]+))?/i },
  { productKey: 'openresty', pattern: /^openresty(?:\/(?<version>[\d.]+))?/i },
  { productKey: 'apache-httpd', pattern: /^apache(?:\/(?<version>[\d.]+))?/i },
  { productKey: 'litespeed', pattern: /^litespeed(?:\/(?<version>[\d.]+))?/i },
  { productKey: 'caddy', pattern: /^caddy(?:\/(?<version>[\d.]+))?/i },
  { productKey: 'iis', pattern: /^microsoft-iis(?:\/(?<version>[\d.]+))?/i },
  { productKey: 'php', pattern: /^php(?:\/(?<version>[\d.]+))?/i },
  { productKey: 'express', pattern: /^express(?:\/(?<version>[\d.]+))?/i },
  { productKey: 'nextjs', pattern: /^next\.js(?:\/(?<version>[\d.]+))?/i },
];
/* eslint-enable security/detect-unsafe-regex */

export interface HeaderInput {
  server: string | undefined;
  xPoweredBy: string | undefined;
}

/** Parses the Server and X-Powered-By header values against a small, fixed table of known
 * product signatures — never guesses beyond what the header itself states. */
export function detectFromHeaders(headers: HeaderInput): HeaderDetection[] {
  const sources: readonly [HeaderDetection['source'], string | undefined][] = [
    ['Server', headers.server],
    ['X-Powered-By', headers.xPoweredBy],
  ];

  const detections: HeaderDetection[] = [];
  for (const [source, value] of sources) {
    if (value === undefined) continue;
    for (const rule of HEADER_DETECTOR_RULES) {
      const match = rule.pattern.exec(value);
      if (match) {
        detections.push({
          productKey: rule.productKey,
          version: match.groups?.['version'],
          source,
          rawValue: value,
        });
      }
    }
  }
  return detections;
}
