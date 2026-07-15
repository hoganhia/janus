import { afterEach, describe, expect, it, vi } from 'vitest';
import { lookupTxt } from '../dns/dns-lookup.js';
import { checkDnsTxtChallenge } from './dns-challenge.js';

vi.mock('../dns/dns-lookup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../dns/dns-lookup.js')>();
  return { ...actual, lookupTxt: vi.fn() };
});

const mockLookupTxt = vi.mocked(lookupTxt);

describe('checkDnsTxtChallenge', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('queries the _janus-verify subdomain of the target', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'not-found', code: 'NXDOMAIN' });

    await checkDnsTxtChallenge('example.com', 'abc123');

    expect(mockLookupTxt).toHaveBeenCalledWith('_janus-verify.example.com', {});
  });

  it('returns true when a TXT record exactly matches the token', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'found', records: [['abc123']] });

    const result = await checkDnsTxtChallenge('example.com', 'abc123');

    expect(result).toBe(true);
  });

  it('joins a TXT record split across multiple chunks before comparing', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'found', records: [['abc', '123']] });

    const result = await checkDnsTxtChallenge('example.com', 'abc123');

    expect(result).toBe(true);
  });

  it('matches one of several TXT records, ignoring the others', async () => {
    mockLookupTxt.mockResolvedValue({
      status: 'found',
      records: [['v=spf1 -all'], ['abc123'], ['some-other-verification=xyz']],
    });

    const result = await checkDnsTxtChallenge('example.com', 'abc123');

    expect(result).toBe(true);
  });

  it('returns false when no TXT record matches the token', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'found', records: [['not-the-token']] });

    const result = await checkDnsTxtChallenge('example.com', 'abc123');

    expect(result).toBe(false);
  });

  it('returns false (not a throw) when the record does not exist', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'not-found', code: 'NXDOMAIN' });

    const result = await checkDnsTxtChallenge('example.com', 'abc123');

    expect(result).toBe(false);
  });

  it('returns false (not a throw) on a DNS error', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'error', code: 'TIMEOUT', message: 'timed out' });

    const result = await checkDnsTxtChallenge('example.com', 'abc123');

    expect(result).toBe(false);
  });

  it('trims whitespace from the record value before comparing', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'found', records: [[' abc123 ']] });

    const result = await checkDnsTxtChallenge('example.com', 'abc123');

    expect(result).toBe(true);
  });
});
