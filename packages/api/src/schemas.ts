// fastify-type-provider-zod's type inference specifically targets zod's v4-core surface (it
// checks schemas against `$ZodType` from `zod/v4/core`) — classic `zod` v3 schemas built via
// `from 'zod'` don't satisfy that check and silently fall back to `unknown` request types, so
// every route-schema file in this package imports from `zod/v4` instead. Verified directly: an
// isolated schema built from classic `zod` typechecked but left `request.body` as `unknown`.
import { z } from 'zod/v4';

export const errorResponseSchema = z.object({
  error: z.string(),
  message: z.string(),
});

// Same-label, same-TLD-length rules as scanDNS's own domain validator (see
// packages/scanners/src/dns/scan-dns.ts) — kept as a separate, simpler regex here since this is
// just an API-boundary format check, not a scan input. Bounded, non-nested quantifiers per
// label (same shape already stress-tested for scanDNS's identical pattern), not vulnerable to
// catastrophic backtracking.
// eslint-disable-next-line security/detect-unsafe-regex
const DOMAIN_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export const domainNameSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(DOMAIN_PATTERN, 'Must be a valid domain name');

export const domainParamSchema = z.object({
  domain: domainNameSchema,
});

export const letterGradeSchema = z.enum(['A', 'B', 'C', 'D', 'F']);
export const domainVerificationStatusSchema = z.enum([
  'UNVERIFIED',
  'PENDING',
  'VERIFIED',
  'FAILED',
  'EXPIRED',
]);
export const domainVerificationMethodSchema = z.enum(['DNS_TXT', 'WELL_KNOWN_FILE']);
export const scanTierSchema = z.enum(['PASSIVE', 'AUTHENTICATED']);
export const legalDocumentTypeSchema = z.enum([
  'TERMS_OF_SERVICE',
  'PRIVACY_POLICY',
  'ACCEPTABLE_USE_POLICY',
]);
