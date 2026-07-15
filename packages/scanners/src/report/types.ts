import { z } from 'zod';
import type { DnsScanResult } from '../dns/types.js';
import type { FingerprintScanResult } from '../fingerprint/types.js';
import type { HeadersScanResult } from '../headers/types.js';
import type { TlsScanResult } from '../tls/types.js';

/**
 * The typed outputs of the individual scanners, as far as `scoreReport` is concerned. Every
 * field is optional: a report can be scored from whatever subset of scans actually ran (e.g. a
 * plain-HTTP-only target has no TLS result at all) — `scoreReport` renormalizes category
 * weights across whatever's present rather than treating a missing scan as a failure.
 */
export interface ScanResults {
  tls?: TlsScanResult;
  headers?: HeadersScanResult;
  dns?: DnsScanResult;
  fingerprint?: FingerprintScanResult;
}

export const reportCategorySchema = z.enum([
  'transportSecurity',
  'headers',
  'emailDnsSecurity',
  'softwareHygiene',
]);
export type ReportCategory = z.infer<typeof reportCategorySchema>;

export const letterGradeSchema = z.enum(['A', 'B', 'C', 'D', 'F']);
export type LetterGrade = z.infer<typeof letterGradeSchema>;

export const categoryScoreSchema = z.object({
  category: reportCategorySchema,
  label: z.string(),
  /** False when the corresponding scan wasn't provided — `score`/`grade` are then `null` and
   * this category's weight is excluded from (not counted against) the overall score. */
  applicable: z.boolean(),
  score: z.number().min(0).max(100).nullable(),
  grade: letterGradeSchema.nullable(),
  /** This category's configured weight (0-1) before renormalization. */
  weight: z.number(),
  /** The weight actually used to compute the overall score: `weight` renormalized across only
   * the applicable categories, so a missing scan never silently drags the overall score down.
   * 0 when `applicable` is false. */
  effectiveWeight: z.number(),
  findingsConsidered: z.number().int(),
});
export type CategoryScore = z.infer<typeof categoryScoreSchema>;

export const scoreReportDisclaimerSchema = z.object({
  summary: z.string(),
  /** Always false. A machine-readable companion to `summary` for UIs that want to render a
   * badge/flag without string-matching the disclaimer text. */
  isComplianceCertification: z.literal(false),
});
export type ScoreReportDisclaimer = z.infer<typeof scoreReportDisclaimerSchema>;

export const scoreReportSchema = z.object({
  generatedAt: z.string(),
  overallScore: z.number().min(0).max(100),
  overallGrade: letterGradeSchema,
  categories: z.array(categoryScoreSchema),
  disclaimer: scoreReportDisclaimerSchema,
});
export type ScoreReport = z.infer<typeof scoreReportSchema>;
