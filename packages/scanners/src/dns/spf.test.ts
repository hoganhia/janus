import { afterEach, describe, expect, it, vi } from 'vitest';
import { lookupTxt } from './dns-lookup.js';
import { evaluateSpf } from './spf.js';

vi.mock('./dns-lookup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./dns-lookup.js')>();
  return { ...actual, lookupTxt: vi.fn() };
});

const mockLookupTxt = vi.mocked(lookupTxt);

function txtFound(...values: string[]) {
  return { status: 'found' as const, records: values.map((v) => [v]) };
}

describe('evaluateSpf', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('fails when there is no SPF record', async () => {
    mockLookupTxt.mockResolvedValueOnce({ status: 'not-found', code: 'NO_DATA' });
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('fail');
  });

  it('ignores unrelated TXT records and finds the SPF one among them', async () => {
    mockLookupTxt.mockResolvedValueOnce(
      txtFound('google-site-verification=abc123', 'v=spf1 -all', 'some-other-txt=value'),
    );
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('pass');
  });

  it('fails when there is more than one SPF record', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=spf1 -all', 'v=spf1 ~all'));
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('fail');
    expect(finding.explanation).toContain('2 SPF records');
  });

  it('passes a record ending in -all (hard fail)', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=spf1 include:_spf.example.com -all'));
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('pass');
  });

  it('warns on ~all (soft fail)', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=spf1 include:_spf.example.com ~all'));
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('warning');
  });

  it('warns on ?all (neutral)', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=spf1 ?all'));
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('warning');
  });

  it('fails on +all (explicitly allows anyone)', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=spf1 +all'));
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('fail');
  });

  it('warns when there is no all mechanism at all', async () => {
    mockLookupTxt.mockResolvedValueOnce(txtFound('v=spf1 include:_spf.example.com'));
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('warning');
  });

  it('fails when the record exceeds the 10-lookup limit', async () => {
    const manyIncludes = Array.from(
      { length: 11 },
      (_, i) => `include:spf${String(i)}.example.com`,
    ).join(' ');
    mockLookupTxt.mockResolvedValueOnce(txtFound(`v=spf1 ${manyIncludes} -all`));
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('fail');
    expect(finding.explanation).toContain('10 DNS lookups');
  });

  it('reports a lookup error as a warning, not a throw', async () => {
    mockLookupTxt.mockResolvedValueOnce({ status: 'error', code: 'TIMEOUT', message: 'timed out' });
    const finding = await evaluateSpf('example.com');
    expect(finding.status).toBe('warning');
  });
});
