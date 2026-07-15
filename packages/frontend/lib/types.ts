/**
 * Mirrors the Fastify API's zod response schemas (packages/api/src/routes/*.ts). The frontend
 * doesn't import @janus/* packages directly — see the package README for why — so these types
 * are kept in sync by hand against the backend schemas.
 */

export type LetterGrade = 'A' | 'B' | 'C' | 'D' | 'F';
export type ScanCheckStatus = 'pass' | 'fail' | 'warning';
export type ReportCategory =
  'transportSecurity' | 'headers' | 'emailDnsSecurity' | 'softwareHygiene';

export interface ScanFinding {
  id: string;
  label: string;
  status: ScanCheckStatus;
  explanation: string;
  details?: Record<string, unknown>;
}

interface ScanSubResult {
  scannedAt: string;
  findings: ScanFinding[];
}

export interface TlsScanResult extends ScanSubResult {
  hostname: string;
  port: number;
}

export interface HeadersScanResult extends ScanSubResult {
  url: string;
}

export interface DnsScanResult extends ScanSubResult {
  domain: string;
}

export interface FingerprintScanResult extends ScanSubResult {
  url: string;
  caveat: string;
}

export interface ScanResults {
  tls?: TlsScanResult;
  headers?: HeadersScanResult;
  dns?: DnsScanResult;
  fingerprint?: FingerprintScanResult;
}

export interface CategoryScore {
  category: ReportCategory;
  label: string;
  applicable: boolean;
  score: number | null;
  grade: LetterGrade | null;
  weight: number;
  effectiveWeight: number;
  findingsConsidered: number;
}

export interface ScoreReportDisclaimer {
  summary: string;
  isComplianceCertification: false;
}

export interface ScoreReport {
  generatedAt: string;
  overallScore: number;
  overallGrade: LetterGrade;
  categories: CategoryScore[];
  disclaimer: ScoreReportDisclaimer;
}

/** Maps a ScoreReport category to the ScanResults key holding its findings. */
export const CATEGORY_TO_RESULTS_KEY: Record<ReportCategory, keyof ScanResults> = {
  transportSecurity: 'tls',
  headers: 'headers',
  emailDnsSecurity: 'dns',
  softwareHygiene: 'fingerprint',
};

// -- POST /scans -------------------------------------------------------------------------------

export interface CreateScanResponse {
  jobId: string;
  targetUrl: string;
}

// -- GET /scans/:id ------------------------------------------------------------------------------

export type ScanJobStatus = 'waiting' | 'active' | 'completed' | 'failed' | 'delayed' | string;

export interface ScanJobResult {
  domain: string;
  scanReportId: string;
  overallScore: number;
  overallGrade: LetterGrade;
}

export interface ScanStatusResponse {
  jobId: string;
  status: ScanJobStatus;
  result?: ScanJobResult;
  failedReason?: string;
}

// -- GET /scan-reports/:id ------------------------------------------------------------------------

export interface ScanReportResponse {
  id: string;
  domain: string;
  scannedAt: string;
  overallScore: number;
  overallGrade: LetterGrade;
  rawResults: ScanResults;
  computedScore: ScoreReport;
}

// -- GET /domains/:domain/history -----------------------------------------------------------------

export interface ScanReportSummary {
  id: string;
  scannedAt: string;
  overallScore: number;
  overallGrade: LetterGrade;
  rawResults: ScanResults;
  computedScore: ScoreReport;
}

export interface DomainHistoryResponse {
  domain: string;
  scans: ScanReportSummary[];
}

export interface ApiErrorBody {
  error: string;
  message: string;
}

// -- POST /abuse-report ---------------------------------------------------------------------------

export interface AbuseReportInput {
  domain: string;
  reason: string;
  details?: string;
  contact?: string;
}

export interface AbuseReportResponse {
  id: string;
}
