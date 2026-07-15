import type { ScanFinding } from '@janus/shared';
import { InsufficientScanDataError } from './errors.js';
import {
  averageFindings,
  CATEGORY_CONFIG,
  scorableFingerprintFindings,
  scoreToGrade,
} from './grading.js';
import type { CategoryScore, ReportCategory, ScanResults, ScoreReport } from './types.js';

const DISCLAIMER_SUMMARY =
  'This report reflects only externally observable, passive signals: TLS configuration, HTTP response headers, DNS/email-authentication records, and software/version details voluntarily disclosed by the server. It is not a penetration test, vulnerability assessment, or compliance audit, and it is not a SOC 2, PCI DSS, ISO 27001, or any other certification. A high score does not mean a system is secure, and a low score does not mean it is out of compliance with any standard — treat it as a starting point for investigation, not a verdict.';

interface CategoryInput {
  category: ReportCategory;
  findings: ScanFinding[] | undefined;
}

function buildCategoryInputs(scanResults: ScanResults): CategoryInput[] {
  return [
    { category: 'transportSecurity', findings: scanResults.tls?.findings },
    { category: 'headers', findings: scanResults.headers?.findings },
    { category: 'emailDnsSecurity', findings: scanResults.dns?.findings },
    {
      category: 'softwareHygiene',
      findings:
        scanResults.fingerprint !== undefined
          ? scorableFingerprintFindings(scanResults.fingerprint.findings)
          : undefined,
    },
  ];
}

/**
 * Scores the typed outputs of the individual scanners (`scanTLS`, `scanHeaders`, `scanDNS`,
 * `fingerprintStack`) into a per-category letter grade plus an overall weighted score. Purely a
 * function of findings already produced elsewhere: no network/DB calls, and it never throws for
 * a scan-side failure — a scanner's own `*.connection` failure finding just scores as a normal
 * `fail`, same as any other finding. It only throws `InsufficientScanDataError` when literally
 * no category has a result to score, since that's a caller bug (call this with at least one
 * scan result) rather than a real-world scan outcome.
 *
 * Category weights favor Transport Security and Headers as the most directly exploitable
 * signals (see `CATEGORY_CONFIG`); a category missing from `scanResults` (e.g. no TLS result
 * for a plain-HTTP target) has its weight redistributed across whichever categories *are*
 * present, rather than being counted as a failure.
 */
export function scoreReport(
  scanResults: ScanResults,
  generatedAt: string = new Date().toISOString(),
): ScoreReport {
  const inputs = buildCategoryInputs(scanResults);
  const present = inputs.filter((c) => c.findings !== undefined);
  if (present.length === 0) {
    throw new InsufficientScanDataError(
      'scoreReport requires at least one scan category result (tls, headers, dns, or fingerprint) to score.',
    );
  }

  const totalPresentWeight = present.reduce(
    (sum, c) => sum + CATEGORY_CONFIG[c.category].weight,
    0,
  );

  const categories: CategoryScore[] = inputs.map(({ category, findings }) => {
    // category is one of the four ReportCategory literals built in buildCategoryInputs above,
    // not attacker/response-controlled.
    // eslint-disable-next-line security/detect-object-injection
    const config = CATEGORY_CONFIG[category];
    if (findings === undefined) {
      return {
        category,
        label: config.label,
        applicable: false,
        score: null,
        grade: null,
        weight: config.weight,
        effectiveWeight: 0,
        findingsConsidered: 0,
      };
    }
    const score = Math.round(averageFindings(findings));
    return {
      category,
      label: config.label,
      applicable: true,
      score,
      grade: scoreToGrade(score),
      weight: config.weight,
      effectiveWeight: config.weight / totalPresentWeight,
      findingsConsidered: findings.length,
    };
  });

  const overallScore = Math.round(
    categories.reduce((sum, c) => sum + (c.score ?? 0) * c.effectiveWeight, 0),
  );

  return {
    generatedAt,
    overallScore,
    overallGrade: scoreToGrade(overallScore),
    categories,
    disclaimer: { summary: DISCLAIMER_SUMMARY, isComplianceCertification: false },
  };
}
