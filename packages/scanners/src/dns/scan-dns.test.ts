import type { ScanFinding } from '@janus/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { evaluateDkim } from './dkim.js';
import { evaluateDmarc } from './dmarc.js';
import { evaluateDnssec } from './dnssec.js';
import { scanDNS } from './scan-dns.js';
import { evaluateSpf } from './spf.js';

vi.mock('./spf.js', () => ({ evaluateSpf: vi.fn() }));
vi.mock('./dmarc.js', () => ({ evaluateDmarc: vi.fn() }));
vi.mock('./dkim.js', () => ({
  evaluateDkim: vi.fn(),
  COMMON_DKIM_SELECTORS: ['default', 'google'],
}));
vi.mock('./dnssec.js', () => ({ evaluateDnssec: vi.fn() }));

const mockSpf = vi.mocked(evaluateSpf);
const mockDmarc = vi.mocked(evaluateDmarc);
const mockDkim = vi.mocked(evaluateDkim);
const mockDnssec = vi.mocked(evaluateDnssec);

function finding(id: string): ScanFinding {
  return { id, label: id, status: 'pass', explanation: 'ok' };
}

describe('scanDNS', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('rejects an obviously invalid domain without calling any evaluator', async () => {
    const result = await scanDNS('not a domain!!');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.id).toBe('dns.domain');
    expect(result.findings[0]?.status).toBe('fail');
    expect(mockSpf).not.toHaveBeenCalled();
  });

  it('rejects an empty domain', async () => {
    const result = await scanDNS('');
    expect(result.findings[0]?.id).toBe('dns.domain');
  });

  it('runs all four checks for a valid domain and assembles their findings', async () => {
    mockSpf.mockResolvedValueOnce(finding('dns.spf'));
    mockDmarc.mockResolvedValueOnce(finding('dns.dmarc'));
    mockDkim.mockResolvedValueOnce(finding('dns.dkim'));
    mockDnssec.mockResolvedValueOnce(finding('dns.dnssec'));

    const result = await scanDNS('example.com');
    expect(result.domain).toBe('example.com');
    const ids = result.findings.map((f) => f.id);
    expect(ids).toEqual(['dns.spf', 'dns.dmarc', 'dns.dkim', 'dns.dnssec']);
  });

  it('passes a custom dkimSelectors option through to evaluateDkim', async () => {
    mockSpf.mockResolvedValueOnce(finding('dns.spf'));
    mockDmarc.mockResolvedValueOnce(finding('dns.dmarc'));
    mockDkim.mockResolvedValueOnce(finding('dns.dkim'));
    mockDnssec.mockResolvedValueOnce(finding('dns.dnssec'));

    await scanDNS('example.com', { dkimSelectors: ['custom1', 'custom2'] });
    expect(mockDkim).toHaveBeenCalledWith('example.com', ['custom1', 'custom2']);
  });

  it('defaults to the common selector list when none is provided', async () => {
    mockSpf.mockResolvedValueOnce(finding('dns.spf'));
    mockDmarc.mockResolvedValueOnce(finding('dns.dmarc'));
    mockDkim.mockResolvedValueOnce(finding('dns.dkim'));
    mockDnssec.mockResolvedValueOnce(finding('dns.dnssec'));

    await scanDNS('example.com');
    expect(mockDkim).toHaveBeenCalledWith('example.com', ['default', 'google']);
  });
});
