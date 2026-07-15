import type { LetterGrade } from '@janus/db';

export interface ScanJobData {
  targetUrl: string;
  /** The original API caller's IP — threaded through to `validateScanTarget`'s abuse-monitoring
   * log and to each scanner's own internal re-validation, not used for anything else here. */
  requesterIp: string;
  userAgent: string;
}

export interface ScanJobResult {
  domain: string;
  scanReportId: string;
  overallScore: number;
  overallGrade: LetterGrade;
}
