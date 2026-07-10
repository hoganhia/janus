import { isIPv4, isIPv6 } from 'node:net';
import { z } from 'zod';
import { isPrivateOrReservedIp } from '../net/ssrf-guard.js';

/**
 * Passive-scan targets only: public http(s) URLs, no credentials in URL.
 *
 * This only rejects hostnames that are *already* IP literals in a private/reserved range —
 * it cannot catch a DNS name that currently resolves publicly but is rebound to a private
 * address later. Callers that actually connect to the target (scanners) must additionally
 * call `resolvePublicAddress` immediately before connecting and pin the returned address,
 * per packages/shared/src/net/ssrf-guard.ts.
 */
export const targetUrlSchema = z
  .string()
  .trim()
  .url({ message: 'Must be a valid URL' })
  .refine((url) => {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }, 'Only http and https URLs are allowed')
  .refine((url) => {
    try {
      const parsed = new URL(url);
      return !parsed.username && !parsed.password;
    } catch {
      return false;
    }
  }, 'URLs must not contain credentials')
  .refine((url) => {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname.toLowerCase();
      if (host === 'localhost' || host.endsWith('.local')) return false;

      const literal = host.replace(/^\[|\]$/g, '');
      if (isIPv4(literal) || isIPv6(literal)) {
        return !isPrivateOrReservedIp(literal);
      }
      return true;
    } catch {
      return false;
    }
  }, 'Target must be a public URL');

export type TargetUrl = z.infer<typeof targetUrlSchema>;
