import type { ScanFinding } from '@janus/shared';
import { describe, expect, it } from 'vitest';
import { averageFindings, scorableFingerprintFindings, scoreToGrade } from './grading.js';

function finding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    id: 'test.finding',
    label: 'Test finding',
    status: 'pass',
    explanation: 'test',
    ...overrides,
  };
}

describe('scoreToGrade', () => {
  it.each<[number, string]>([
    [100, 'A'],
    [90, 'A'],
    [89, 'B'],
    [80, 'B'],
    [79, 'C'],
    [70, 'C'],
    [69, 'D'],
    [60, 'D'],
    [59, 'F'],
    [0, 'F'],
  ])('scores %i as %s', (score, expected) => {
    expect(scoreToGrade(score)).toBe(expected);
  });
});

describe('averageFindings', () => {
  it('returns 100 for an empty finding list', () => {
    expect(averageFindings([])).toBe(100);
  });

  it('returns 100 when every finding passes', () => {
    expect(averageFindings([finding({ status: 'pass' }), finding({ status: 'pass' })])).toBe(100);
  });

  it('returns 0 when every finding fails', () => {
    expect(averageFindings([finding({ status: 'fail' }), finding({ status: 'fail' })])).toBe(0);
  });

  it('returns 50 when every finding warns', () => {
    expect(averageFindings([finding({ status: 'warning' })])).toBe(50);
  });

  it('averages a mix of pass and fail', () => {
    expect(averageFindings([finding({ status: 'pass' }), finding({ status: 'fail' })])).toBe(50);
  });

  it('averages a mix of pass, warning, and fail', () => {
    const findings = [
      finding({ status: 'pass' }),
      finding({ status: 'warning' }),
      finding({ status: 'fail' }),
    ];
    expect(averageFindings(findings)).toBeCloseTo(50, 5);
  });
});

describe('scorableFingerprintFindings', () => {
  it('keeps a connection-failure finding', () => {
    const findings = [finding({ id: 'fingerprint.connection', status: 'fail' })];
    expect(scorableFingerprintFindings(findings)).toEqual(findings);
  });

  it('keeps CVE findings', () => {
    const findings = [finding({ id: 'fingerprint.cve.CVE-2021-23017', status: 'fail' })];
    expect(scorableFingerprintFindings(findings)).toEqual(findings);
  });

  it('drops purely informational detection findings', () => {
    const findings = [finding({ id: 'fingerprint.detected.nginx', status: 'warning' })];
    expect(scorableFingerprintFindings(findings)).toEqual([]);
  });

  it('drops generic path-signal findings', () => {
    const findings = [finding({ id: 'fingerprint.path./vendor/', status: 'warning' })];
    expect(scorableFingerprintFindings(findings)).toEqual([]);
  });

  it('filters a mixed list down to only the scorable findings', () => {
    const connection = finding({ id: 'fingerprint.connection', status: 'fail' });
    const cve = finding({ id: 'fingerprint.cve.CVE-2020-0001', status: 'warning' });
    const detected = finding({ id: 'fingerprint.detected.wordpress', status: 'warning' });
    const path = finding({ id: 'fingerprint.path./wp-login.php', status: 'warning' });
    expect(scorableFingerprintFindings([connection, cve, detected, path])).toEqual([
      connection,
      cve,
    ]);
  });
});
