import type { Answer } from 'dns-packet';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { evaluateDnssec } from './dnssec.js';
import { queryRawDns, RawDnsQueryError } from './raw-dns-query.js';

vi.mock('./raw-dns-query.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./raw-dns-query.js')>();
  return { ...actual, queryRawDns: vi.fn() };
});

const mockQuery = vi.mocked(queryRawDns);

const SOME_ANSWER = [{ name: 'example.com', type: 'DS' }] as unknown as Answer[];

describe('evaluateDnssec', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('passes when both DS and DNSKEY are present', async () => {
    mockQuery.mockResolvedValue(SOME_ANSWER);
    const finding = await evaluateDnssec('example.com');
    expect(finding.status).toBe('pass');
  });

  it('warns when DNSKEY is present but DS is missing (incomplete chain of trust)', async () => {
    mockQuery.mockImplementation((_name, type) =>
      Promise.resolve(type === 'DNSKEY' ? SOME_ANSWER : []),
    );
    const finding = await evaluateDnssec('example.com');
    expect(finding.status).toBe('warning');
    expect(finding.explanation).toContain('incomplete');
  });

  it('fails when neither DS nor DNSKEY is present', async () => {
    mockQuery.mockResolvedValue([]);
    const finding = await evaluateDnssec('example.com');
    expect(finding.status).toBe('fail');
  });

  it('fails cleanly on NXDOMAIN', async () => {
    mockQuery.mockRejectedValue(new RawDnsQueryError('nope', 'NXDOMAIN'));
    const finding = await evaluateDnssec('nonexistent.example');
    expect(finding.status).toBe('fail');
    expect(finding.explanation).toContain('does not exist');
  });

  it('warns (not throws) when both queries fail', async () => {
    mockQuery.mockRejectedValue(new RawDnsQueryError('timed out', 'TIMEOUT'));
    const finding = await evaluateDnssec('example.com');
    expect(finding.status).toBe('warning');
  });

  it('warns when only one of the two queries fails', async () => {
    mockQuery.mockImplementation((_name, type) => {
      if (type === 'DS') return Promise.reject(new RawDnsQueryError('timed out', 'TIMEOUT'));
      return Promise.resolve(SOME_ANSWER);
    });
    const finding = await evaluateDnssec('example.com');
    expect(finding.status).toBe('warning');
    expect(finding.explanation).toContain('could not be fully determined');
  });
});
