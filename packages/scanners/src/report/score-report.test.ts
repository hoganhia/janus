import type { ScanFinding } from '@janus/shared';
import { describe, expect, it } from 'vitest';
import { InsufficientScanDataError } from './errors.js';
import { scoreReport } from './score-report.js';
import type { ScanResults } from './types.js';

function finding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    id: 'test.finding',
    label: 'Test finding',
    status: 'pass',
    explanation: 'test',
    ...overrides,
  };
}

function tlsResult(findings: ScanFinding[]): NonNullable<ScanResults['tls']> {
  return { hostname: 'example.com', port: 443, scannedAt: '2026-07-13T00:00:00.000Z', findings };
}

function headersResult(findings: ScanFinding[]): NonNullable<ScanResults['headers']> {
  return { url: 'https://example.com/', scannedAt: '2026-07-13T00:00:00.000Z', findings };
}

function dnsResult(findings: ScanFinding[]): NonNullable<ScanResults['dns']> {
  return { domain: 'example.com', scannedAt: '2026-07-13T00:00:00.000Z', findings };
}

function fingerprintResult(findings: ScanFinding[]): NonNullable<ScanResults['fingerprint']> {
  return {
    url: 'https://example.com/',
    scannedAt: '2026-07-13T00:00:00.000Z',
    caveat: 'probabilistic',
    findings,
  };
}

const GENERATED_AT = '2026-07-13T12:00:00.000Z';

describe('scoreReport', () => {
  it('throws InsufficientScanDataError when no category has a result', () => {
    expect(() => scoreReport({}, GENERATED_AT)).toThrow(InsufficientScanDataError);
  });

  it('scores a fully-passing scan as 100/A across every category', () => {
    const scanResults: ScanResults = {
      tls: tlsResult([finding({ status: 'pass' })]),
      headers: headersResult([finding({ status: 'pass' })]),
      dns: dnsResult([finding({ status: 'pass' })]),
      fingerprint: fingerprintResult([]),
    };

    const report = scoreReport(scanResults, GENERATED_AT);

    expect(report.generatedAt).toBe(GENERATED_AT);
    expect(report.overallScore).toBe(100);
    expect(report.overallGrade).toBe('A');
    for (const category of report.categories) {
      expect(category.applicable).toBe(true);
      expect(category.score).toBe(100);
      expect(category.grade).toBe('A');
    }
  });

  it('scores a fully-failing scan as 0/F', () => {
    const scanResults: ScanResults = {
      tls: tlsResult([finding({ status: 'fail' })]),
      headers: headersResult([finding({ status: 'fail' })]),
      dns: dnsResult([finding({ status: 'fail' })]),
      fingerprint: fingerprintResult([finding({ id: 'fingerprint.connection', status: 'fail' })]),
    };

    const report = scoreReport(scanResults, GENERATED_AT);

    expect(report.overallScore).toBe(0);
    expect(report.overallGrade).toBe('F');
  });

  it('marks a missing category as not applicable and excludes its weight from the overall score', () => {
    const scanResults: ScanResults = {
      tls: tlsResult([finding({ status: 'pass' })]),
      headers: headersResult([finding({ status: 'pass' })]),
      // dns and fingerprint omitted entirely
    };

    const report = scoreReport(scanResults, GENERATED_AT);

    const dnsCategory = report.categories.find((c) => c.category === 'emailDnsSecurity');
    const hygieneCategory = report.categories.find((c) => c.category === 'softwareHygiene');
    expect(dnsCategory).toMatchObject({
      applicable: false,
      score: null,
      grade: null,
      effectiveWeight: 0,
    });
    expect(hygieneCategory).toMatchObject({
      applicable: false,
      score: null,
      grade: null,
      effectiveWeight: 0,
    });

    // Both present categories (tls + headers) are weighted 0.3 each in CATEGORY_CONFIG, so with
    // only those two present, each should be renormalized to 0.5 of the overall score.
    const tlsCategory = report.categories.find((c) => c.category === 'transportSecurity');
    const headersCategory = report.categories.find((c) => c.category === 'headers');
    expect(tlsCategory?.effectiveWeight).toBeCloseTo(0.5, 5);
    expect(headersCategory?.effectiveWeight).toBeCloseTo(0.5, 5);
    expect(report.overallScore).toBe(100);
  });

  it('renormalizes to a single category carrying the full weight when only it is present', () => {
    const scanResults: ScanResults = {
      dns: dnsResult([finding({ status: 'warning' })]),
    };

    const report = scoreReport(scanResults, GENERATED_AT);

    const dnsCategory = report.categories.find((c) => c.category === 'emailDnsSecurity');
    expect(dnsCategory?.effectiveWeight).toBeCloseTo(1, 5);
    expect(dnsCategory?.score).toBe(50);
    expect(report.overallScore).toBe(50);
    expect(report.overallGrade).toBe('F');
  });

  it('computes a non-trivial weighted overall score across all four categories', () => {
    // tls=75 (0.3), headers=50 (0.3), dns=100 (0.2), fingerprint=100/no scorable findings (0.2)
    // -> 75*0.3 + 50*0.3 + 100*0.2 + 100*0.2 = 22.5 + 15 + 20 + 20 = 77.5 -> rounds to 78 -> grade C
    const scanResults: ScanResults = {
      tls: tlsResult([finding({ status: 'pass' }), finding({ status: 'warning' })]),
      headers: headersResult([finding({ status: 'pass' }), finding({ status: 'fail' })]),
      dns: dnsResult([finding({ status: 'pass' })]),
      fingerprint: fingerprintResult([
        finding({ id: 'fingerprint.detected.nginx', status: 'warning' }),
      ]),
    };

    const report = scoreReport(scanResults, GENERATED_AT);

    expect(report.categories.find((c) => c.category === 'transportSecurity')?.score).toBe(75);
    expect(report.categories.find((c) => c.category === 'headers')?.score).toBe(50);
    expect(report.categories.find((c) => c.category === 'emailDnsSecurity')?.score).toBe(100);
    expect(report.categories.find((c) => c.category === 'softwareHygiene')?.score).toBe(100);
    expect(report.overallScore).toBe(78);
    expect(report.overallGrade).toBe('C');
  });

  it('does not penalize software hygiene for purely informational fingerprint detections', () => {
    const scanResults: ScanResults = {
      fingerprint: fingerprintResult([
        finding({ id: 'fingerprint.detected.nginx', status: 'warning' }),
        finding({ id: 'fingerprint.detected.wordpress', status: 'warning' }),
        finding({ id: 'fingerprint.path./vendor/', status: 'warning' }),
      ]),
    };

    const report = scoreReport(scanResults, GENERATED_AT);

    const hygieneCategory = report.categories.find((c) => c.category === 'softwareHygiene');
    expect(hygieneCategory?.applicable).toBe(true);
    expect(hygieneCategory?.score).toBe(100);
    expect(hygieneCategory?.grade).toBe('A');
    expect(hygieneCategory?.findingsConsidered).toBe(0);
  });

  it('does penalize software hygiene for a real matched CVE', () => {
    const scanResults: ScanResults = {
      fingerprint: fingerprintResult([
        finding({ id: 'fingerprint.detected.nginx', status: 'warning' }),
        finding({ id: 'fingerprint.cve.CVE-2021-23017', status: 'fail' }),
      ]),
    };

    const report = scoreReport(scanResults, GENERATED_AT);

    const hygieneCategory = report.categories.find((c) => c.category === 'softwareHygiene');
    expect(hygieneCategory?.score).toBe(0);
    expect(hygieneCategory?.grade).toBe('F');
    expect(hygieneCategory?.findingsConsidered).toBe(1);
  });

  it('always returns a disclaimer that is explicitly not a compliance certification', () => {
    const report = scoreReport({ dns: dnsResult([finding({ status: 'pass' })]) }, GENERATED_AT);

    expect(report.disclaimer.isComplianceCertification).toBe(false);
    expect(report.disclaimer.summary).toMatch(/SOC 2/);
    expect(report.disclaimer.summary).toMatch(/not a penetration test/i);
  });

  it('defaults generatedAt to the current time when not provided', () => {
    const before = Date.now();
    const report = scoreReport({ dns: dnsResult([finding({ status: 'pass' })]) });
    const after = Date.now();

    const generatedAtMs = new Date(report.generatedAt).getTime();
    expect(generatedAtMs).toBeGreaterThanOrEqual(before);
    expect(generatedAtMs).toBeLessThanOrEqual(after);
  });
});
