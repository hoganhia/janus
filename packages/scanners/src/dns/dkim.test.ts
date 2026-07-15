import { afterEach, describe, expect, it, vi } from 'vitest';
import { evaluateDkim } from './dkim.js';
import { lookupTxt } from './dns-lookup.js';

vi.mock('./dns-lookup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./dns-lookup.js')>();
  return { ...actual, lookupTxt: vi.fn() };
});

const mockLookupTxt = vi.mocked(lookupTxt);

describe('evaluateDkim', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('passes when a selector has a real key', async () => {
    mockLookupTxt.mockImplementation((name: string) => {
      if (name.startsWith('default._domainkey.')) {
        return Promise.resolve({
          status: 'found' as const,
          records: [['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC']],
        });
      }
      return Promise.resolve({ status: 'not-found' as const, code: 'NO_DATA' as const });
    });

    const finding = await evaluateDkim('example.com', ['default', 'google']);
    expect(finding.status).toBe('pass');
    expect(finding.explanation).toContain('default');
  });

  it('treats an empty p= (revoked key) as not found, not as a pass', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'found', records: [['v=DKIM1; p=']] });
    const finding = await evaluateDkim('example.com', ['default', 'google']);
    expect(finding.status).toBe('warning');
  });

  it('warns (not fails) when no common selector has a record', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'not-found', code: 'NO_DATA' });
    const finding = await evaluateDkim('example.com', ['default', 'google']);
    expect(finding.status).toBe('warning');
    expect(finding.explanation).toContain('does not necessarily mean');
  });

  it('checks every selector name at <selector>._domainkey.<domain>', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'not-found', code: 'NO_DATA' });
    await evaluateDkim('example.com', ['foo', 'bar']);
    expect(mockLookupTxt).toHaveBeenCalledWith('foo._domainkey.example.com');
    expect(mockLookupTxt).toHaveBeenCalledWith('bar._domainkey.example.com');
  });

  it('never throws when some lookups error out', async () => {
    mockLookupTxt.mockResolvedValue({ status: 'error', code: 'TIMEOUT', message: 'timed out' });
    const finding = await evaluateDkim('example.com', ['default']);
    expect(finding.status).toBe('warning');
  });
});
