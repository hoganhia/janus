import type { ScanCheckStatus, ScanFinding } from '@janus/shared';
import type { LetterGrade, ReportCategory } from './types.js';

export interface CategoryConfig {
  label: string;
  /**
   * 0-1, sums to 1 across all four categories. TLS and headers are weighted highest since they
   * most directly reflect exploitable transport/response-level security posture; DNS/email
   * authentication and software-hygiene signals are weighted lower — both are meaningful but
   * more indirect (email-spoofing exposure, a hint about outstanding CVEs) than a live TLS or
   * header misconfiguration.
   */
  weight: number;
}

export const CATEGORY_CONFIG: Readonly<Record<ReportCategory, CategoryConfig>> = {
  transportSecurity: { label: 'Transport Security', weight: 0.3 },
  headers: { label: 'Headers', weight: 0.3 },
  emailDnsSecurity: { label: 'Email/DNS Security', weight: 0.2 },
  softwareHygiene: { label: 'Software Hygiene', weight: 0.2 },
};

const STATUS_POINTS: Readonly<Record<ScanCheckStatus, number>> = {
  pass: 100,
  warning: 50,
  fail: 0,
};

const GRADE_THRESHOLDS: readonly [number, LetterGrade][] = [
  [90, 'A'],
  [80, 'B'],
  [70, 'C'],
  [60, 'D'],
];

export function scoreToGrade(score: number): LetterGrade {
  for (const [threshold, grade] of GRADE_THRESHOLDS) {
    if (score >= threshold) return grade;
  }
  return 'F';
}

/**
 * Averages a category's findings into a 0-100 score (pass=100, warning=50, fail=0, uniformly —
 * the shared `ScanFinding` shape has no per-finding severity/weight to draw on). An empty
 * finding list scores 100: no scorable checks turned up anything wrong, so there's nothing to
 * penalize. See `scorableFingerprintFindings` for the one category where "empty after
 * filtering" is a real, common case rather than an edge case.
 */
export function averageFindings(findings: readonly ScanFinding[]): number {
  if (findings.length === 0) return 100;
  const total = findings.reduce((sum, f) => sum + STATUS_POINTS[f.status], 0);
  return total / findings.length;
}

/**
 * Software Hygiene's findings aren't all scorable the way every other category's are: most
 * fingerprint findings (`fingerprint.detected.*`, `fingerprint.path.*`) just report what was
 * passively observed and are always `warning` regardless of whether anything is actually
 * wrong — averaging those in would penalize a site for simply being fingerprintable, not for
 * having a problem. Only a failed connection (`fingerprint.connection`) or an actual matched
 * CVE (`fingerprint.cve.*`, already scored fail/warning by severity+age in cve-matching.ts)
 * reflect a real hygiene signal, so only those count toward the score.
 */
export function scorableFingerprintFindings(findings: readonly ScanFinding[]): ScanFinding[] {
  return findings.filter(
    (f) => f.id === 'fingerprint.connection' || f.id.startsWith('fingerprint.cve.'),
  );
}
