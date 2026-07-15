import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkOptOut } from './check-opt-out.js';

const resolveTxt = vi.fn();
const cancel = vi.fn();

vi.mock('node:dns', () => {
  class Resolver {
    resolveTxt = resolveTxt;
    cancel = cancel;
  }
  return { default: { promises: { Resolver } } };
});

describe('checkOptOut', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('queries the _janus-opt-out label under the target hostname', async () => {
    resolveTxt.mockResolvedValueOnce([['true']]);
    await checkOptOut('example.com');
    expect(resolveTxt).toHaveBeenCalledWith('_janus-opt-out.example.com');
  });

  it('lowercases the hostname before building the query name', async () => {
    resolveTxt.mockResolvedValueOnce([['true']]);
    await checkOptOut('Example.COM');
    expect(resolveTxt).toHaveBeenCalledWith('_janus-opt-out.example.com');
  });

  it('returns true when a TXT record value is exactly "true"', async () => {
    resolveTxt.mockResolvedValueOnce([['true']]);
    await expect(checkOptOut('opted-out.example')).resolves.toBe(true);
  });

  it('returns true when "true" is spread across multiple TXT chunks', async () => {
    resolveTxt.mockResolvedValueOnce([['tr', 'ue']]);
    await expect(checkOptOut('opted-out.example')).resolves.toBe(true);
  });

  it('is case-insensitive and trims whitespace on the record value', async () => {
    resolveTxt.mockResolvedValueOnce([[' TRUE ']]);
    await expect(checkOptOut('opted-out.example')).resolves.toBe(true);
  });

  it('returns false when no TXT record matches "true"', async () => {
    resolveTxt.mockResolvedValueOnce([['false'], ['some-other-value']]);
    await expect(checkOptOut('normal.example')).resolves.toBe(false);
  });

  it('returns false (fails open) when the record does not exist', async () => {
    resolveTxt.mockRejectedValueOnce(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }));
    await expect(checkOptOut('normal.example')).resolves.toBe(false);
  });

  it('returns false (fails open) on a DNS timeout or other resolver error', async () => {
    resolveTxt.mockRejectedValueOnce(new Error('timeout'));
    await expect(checkOptOut('normal.example')).resolves.toBe(false);
  });
});
