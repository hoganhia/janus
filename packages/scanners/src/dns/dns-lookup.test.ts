import { describe, expect, it } from 'vitest';
import { joinTxtRecord, lookupTxt } from './dns-lookup.js';

/** Hits real DNS — the NXDOMAIN/ENODATA/timeout error codes this module maps are Node's own
 * runtime behavior (ENOTFOUND, ENODATA, ECANCELLED), verified directly rather than assumed. */
describe('lookupTxt (real DNS)', () => {
  it('finds and correctly joins a real TXT record', async () => {
    const result = await lookupTxt('example.com');
    expect(result.status).toBe('found');
    if (result.status === 'found') {
      const values = result.records.map(joinTxtRecord);
      expect(values.some((v) => v.startsWith('v=spf1'))).toBe(true);
    }
  });

  it('maps NXDOMAIN to a typed not-found result, not a throw', async () => {
    const result = await lookupTxt('this-domain-should-not-exist-abcxyz123.com');
    expect(result).toEqual({ status: 'not-found', code: 'NXDOMAIN' });
  });

  it('maps ENODATA (domain exists, no record of this type) to a typed not-found result', async () => {
    const result = await lookupTxt('_dmarc.neverssl.com');
    expect(result).toEqual({ status: 'not-found', code: 'NO_DATA' });
  });

  it('maps a real timeout to a typed error result, not a throw or a hang', async () => {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737) — reserved for documentation, guaranteed unroutable.
    const result = await lookupTxt('example.com', { servers: ['192.0.2.1'], timeoutMs: 500 });
    expect(result.status).toBe('error');
    if (result.status === 'error') {
      expect(result.code).toBe('TIMEOUT');
    }
  }, 10000);
});
