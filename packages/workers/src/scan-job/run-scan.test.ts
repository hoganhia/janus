import { findDomainByName, recordScanReport, type Domain, type ScanReport } from '@janus/db';
import {
  fingerprintStack,
  scanDNS,
  scanHeaders,
  scanTLS,
  scoreReport,
  type DnsScanResult,
  type FingerprintScanResult,
  type HeadersScanResult,
  type ScoreReport,
  type TlsScanResult,
} from '@janus/scanners';
import { validateScanTarget, type ValidatedScanTarget } from '@janus/shared';
import { UnrecoverableError } from 'bullmq';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runScanJob } from './run-scan.js';
import type { ScanJobData } from './types.js';

vi.mock('@janus/shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/shared')>();
  return { ...actual, validateScanTarget: vi.fn() };
});
vi.mock('@janus/scanners', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/scanners')>();
  return {
    ...actual,
    scanTLS: vi.fn(),
    scanHeaders: vi.fn(),
    scanDNS: vi.fn(),
    fingerprintStack: vi.fn(),
    scoreReport: vi.fn(),
  };
});
vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return { ...actual, recordScanReport: vi.fn(), findDomainByName: vi.fn() };
});

const mockValidate = vi.mocked(validateScanTarget);
const mockScanTls = vi.mocked(scanTLS);
const mockScanHeaders = vi.mocked(scanHeaders);
const mockScanDns = vi.mocked(scanDNS);
const mockFingerprintStack = vi.mocked(fingerprintStack);
const mockScoreReport = vi.mocked(scoreReport);
const mockRecordScanReport = vi.mocked(recordScanReport);
const mockFindDomainByName = vi.mocked(findDomainByName);

const JOB_DATA: ScanJobData = {
  targetUrl: 'https://example.com/',
  requesterIp: '203.0.113.9',
  userAgent: 'UA/1.0',
};

const VALIDATED: ValidatedScanTarget = {
  requestedUrl: 'https://example.com/',
  finalUrl: 'https://example.com/',
  pinnedAddress: '93.184.216.34',
  family: 4,
  redirectCount: 0,
};

function tlsResult(overrides: Partial<TlsScanResult> = {}): TlsScanResult {
  return {
    hostname: 'example.com',
    port: 443,
    scannedAt: '2026-07-13T00:00:00.000Z',
    findings: [],
    ...overrides,
  };
}
function headersResult(overrides: Partial<HeadersScanResult> = {}): HeadersScanResult {
  return {
    url: 'https://example.com/',
    scannedAt: '2026-07-13T00:00:00.000Z',
    findings: [],
    ...overrides,
  };
}
function dnsResult(overrides: Partial<DnsScanResult> = {}): DnsScanResult {
  return {
    domain: 'example.com',
    scannedAt: '2026-07-13T00:00:00.000Z',
    findings: [],
    ...overrides,
  };
}
function fingerprintResult(overrides: Partial<FingerprintScanResult> = {}): FingerprintScanResult {
  return {
    url: 'https://example.com/',
    scannedAt: '2026-07-13T00:00:00.000Z',
    caveat: 'probabilistic',
    findings: [],
    ...overrides,
  };
}
function fakeScoreReport(): ScoreReport {
  return {
    generatedAt: '2026-07-13T00:00:00.000Z',
    overallScore: 88,
    overallGrade: 'B',
    categories: [],
    disclaimer: { summary: 'test disclaimer', isComplianceCertification: false },
  };
}
function fakeScanReport(): ScanReport {
  return {
    id: 'report-1',
    domainId: 'domain-1',
    scannedAt: new Date('2026-07-13T00:00:00.000Z'),
    rawResults: {},
    computedScore: {},
    overallGrade: 'B',
    overallScore: 88,
    createdAt: new Date('2026-07-13T00:00:00.000Z'),
  };
}

function setupHappyPath(): void {
  mockFindDomainByName.mockResolvedValue(null);
  mockValidate.mockResolvedValue(VALIDATED);
  mockScanTls.mockResolvedValue(tlsResult());
  mockScanHeaders.mockResolvedValue(headersResult());
  mockScanDns.mockResolvedValue(dnsResult());
  mockFingerprintStack.mockResolvedValue(fingerprintResult());
  mockScoreReport.mockReturnValue(fakeScoreReport());
  mockRecordScanReport.mockResolvedValue(fakeScanReport());
}

describe('runScanJob', () => {
  afterEach(() => {
    vi.resetAllMocks();
    vi.useRealTimers();
  });

  it('runs all four scanners, scores, and persists the report on the happy path', async () => {
    setupHappyPath();

    const result = await runScanJob(JOB_DATA);

    expect(mockFindDomainByName).toHaveBeenCalledWith('example.com');
    expect(mockValidate).toHaveBeenCalledWith(JOB_DATA.targetUrl, {
      requesterIp: JOB_DATA.requesterIp,
      userAgent: JOB_DATA.userAgent,
      skipOptOutCheck: false,
    });
    expect(mockScanTls).toHaveBeenCalledWith('example.com', VALIDATED.pinnedAddress, {
      timeoutMs: 8000,
    });
    expect(mockScanHeaders).toHaveBeenCalledWith(
      VALIDATED.finalUrl,
      expect.objectContaining({ requesterIp: JOB_DATA.requesterIp, userAgent: JOB_DATA.userAgent }),
    );
    expect(mockScanDns).toHaveBeenCalledWith('example.com');
    expect(mockFingerprintStack).toHaveBeenCalledWith(
      VALIDATED.finalUrl,
      expect.objectContaining({ requesterIp: JOB_DATA.requesterIp, userAgent: JOB_DATA.userAgent }),
    );

    expect(mockScoreReport).toHaveBeenCalledTimes(1);
    const [scanResultsArg] = mockScoreReport.mock.calls[0] ?? [];
    expect(scanResultsArg?.tls).toEqual(tlsResult());
    expect(scanResultsArg?.headers).toEqual(headersResult());
    expect(scanResultsArg?.dns).toEqual(dnsResult());
    expect(scanResultsArg?.fingerprint).toEqual(fingerprintResult());

    expect(mockRecordScanReport).toHaveBeenCalledWith(
      expect.objectContaining({
        domain: 'example.com',
        overallGrade: 'B',
        overallScore: 88,
      }),
    );

    expect(result).toEqual({
      domain: 'example.com',
      scanReportId: 'report-1',
      overallScore: 88,
      overallGrade: 'B',
    });
  });

  it('converts a deterministic target rejection into an UnrecoverableError', async () => {
    const { ScanTargetRejectedError } =
      await vi.importActual<typeof import('@janus/shared')>('@janus/shared');
    mockValidate.mockRejectedValue(
      new ScanTargetRejectedError('PRIVATE_ADDRESS', 'Target must resolve to a public address'),
    );

    await expect(runScanJob(JOB_DATA)).rejects.toThrow(UnrecoverableError);
    expect(mockScanTls).not.toHaveBeenCalled();
  });

  it('converts an OPTED_OUT rejection into an UnrecoverableError too', async () => {
    mockFindDomainByName.mockResolvedValue(null);
    const { ScanTargetRejectedError } =
      await vi.importActual<typeof import('@janus/shared')>('@janus/shared');
    mockValidate.mockRejectedValue(
      new ScanTargetRejectedError('OPTED_OUT', 'Target has opted out of scanning'),
    );

    await expect(runScanJob(JOB_DATA)).rejects.toThrow(UnrecoverableError);
    expect(mockScanTls).not.toHaveBeenCalled();
  });

  it('skips the opt-out check when the target domain is AUTHENTICATED (verified owner)', async () => {
    mockFindDomainByName.mockResolvedValue({ scanTier: 'AUTHENTICATED' } as Domain);
    mockValidate.mockResolvedValue(VALIDATED);
    mockScanTls.mockResolvedValue(tlsResult());
    mockScanHeaders.mockResolvedValue(headersResult());
    mockScanDns.mockResolvedValue(dnsResult());
    mockFingerprintStack.mockResolvedValue(fingerprintResult());
    mockScoreReport.mockReturnValue(fakeScoreReport());
    mockRecordScanReport.mockResolvedValue(fakeScanReport());

    await runScanJob(JOB_DATA);

    expect(mockValidate).toHaveBeenCalledWith(
      JOB_DATA.targetUrl,
      expect.objectContaining({ skipOptOutCheck: true }),
    );
  });

  it('does not convert a PROBE_FAILED rejection — lets it retry normally', async () => {
    const { ScanTargetRejectedError } =
      await vi.importActual<typeof import('@janus/shared')>('@janus/shared');
    const probeFailure = new ScanTargetRejectedError('PROBE_FAILED', 'Failed to validate target');
    mockValidate.mockRejectedValue(probeFailure);

    await expect(runScanJob(JOB_DATA)).rejects.toBe(probeFailure);
  });

  it('propagates a transient error from recordScanReport unchanged (so BullMQ retries)', async () => {
    setupHappyPath();
    const dbError = new Error('connection terminated unexpectedly');
    mockRecordScanReport.mockRejectedValue(dbError);

    await expect(runScanJob(JOB_DATA)).rejects.toBe(dbError);
  });

  describe('per-scanner timeout backstop', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    it('falls back to a tls.connection failure finding when scanTLS hangs past its budget, without dropping the other scanners', async () => {
      mockValidate.mockResolvedValue(VALIDATED);
      mockScanTls.mockImplementation(() => new Promise(() => {})); // never resolves
      mockScanHeaders.mockResolvedValue(headersResult());
      mockScanDns.mockResolvedValue(dnsResult());
      mockFingerprintStack.mockResolvedValue(fingerprintResult());
      mockScoreReport.mockReturnValue(fakeScoreReport());
      mockRecordScanReport.mockResolvedValue(fakeScanReport());

      const resultPromise = runScanJob(JOB_DATA);
      await vi.runAllTimersAsync();
      await resultPromise;

      const [scanResultsArg] = mockScoreReport.mock.calls[0] ?? [];
      expect(scanResultsArg?.tls?.findings).toHaveLength(1);
      expect(scanResultsArg?.tls?.findings[0]).toMatchObject({
        id: 'tls.connection',
        status: 'fail',
      });
      // The other three scanners' real results are still used, unaffected by TLS timing out.
      expect(scanResultsArg?.headers).toEqual(headersResult());
      expect(scanResultsArg?.dns).toEqual(dnsResult());
      expect(scanResultsArg?.fingerprint).toEqual(fingerprintResult());
    });
  });
});
