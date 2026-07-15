import { afterEach, describe, expect, it, vi } from 'vitest';
import { evaluateDmarc } from './dmarc.js';
import { lookupTxt } from './dns-lookup.js';

vi.mock('./dns-lookup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./dns-lookup.js')>();
  return { ...actual, lookupTxt: vi.fn() };
});

const mockLookupTxt = vi.mocked(lookupTxt);

function txtFound(value: string) {
  return { status: 'found' as const, records: [[value]] };
}

describe('evaluateDmarc', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('queries _dmarc.<domain>', async () => {
    mockLookupTxt.mockResolvedValueOnce({ status: 'not-found', code: 'NO_DATA' });
    await evaluateDmarc('example.com');
    expect(mockLookupTxt).toHaveBeenCalledWith('_dmarc.example.com');
  });

  it('fails when there is no DMARC record', async () => {
    mockLookupTxt.mockResolvedValueOnce({ status: 'not-found', code: 'NO_DATA' });
    const finding = await evaluateDmarc('example.com');
    expect(finding.status).toBe('fail');
  });

  it('passes p=reject', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=DMARC1; p=reject'));
    const finding = await evaluateDmarc('example.com');
    expect(finding.status).toBe('pass');
  });

  it('passes p=quarantine', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=DMARC1; p=quarantine'));
    const finding = await evaluateDmarc('example.com');
    expect(finding.status).toBe('pass');
  });

  it('warns on p=none (monitoring only)', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=DMARC1; p=none'));
    const finding = await evaluateDmarc('example.com');
    expect(finding.status).toBe('warning');
  });

  it('fails on an unrecognized policy value', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=DMARC1; p=bogus'));
    const finding = await evaluateDmarc('example.com');
    expect(finding.status).toBe('fail');
  });

  it('downgrades an otherwise-passing policy to warning when pct < 100', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=DMARC1; p=reject; pct=50'));
    const finding = await evaluateDmarc('example.com');
    expect(finding.status).toBe('warning');
    expect(finding.explanation).toContain('50%');
  });

  it('reports a lookup error as a warning, not a throw', async () => {
    mockLookupTxt.mockResolvedValueOnce({ status: 'error', code: 'OTHER', message: 'boom' });
    const finding = await evaluateDmarc('example.com');
    expect(finding.status).toBe('warning');
  });
});
