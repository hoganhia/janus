import type {
  AbuseReportInput,
  AbuseReportResponse,
  ApiErrorBody,
  CreateScanResponse,
  DomainHistoryResponse,
  LegalVersionsResponse,
  ScanReportResponse,
  ScanStatusResponse,
} from './types';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3000/api/v1';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ApiErrorBody,
  ) {
    super(body.message);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  });

  if (!res.ok) {
    const body = (await res.json()) as ApiErrorBody;
    throw new ApiError(res.status, body);
  }

  return res.json() as Promise<T>;
}

export function createScan(targetUrl: string, attestation: boolean): Promise<CreateScanResponse> {
  return request<CreateScanResponse>('/scans', {
    method: 'POST',
    body: JSON.stringify({ targetUrl, attestation }),
  });
}

export function getScanStatus(jobId: string): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>(`/scans/${encodeURIComponent(jobId)}`);
}

export function getScanReport(reportId: string): Promise<ScanReportResponse> {
  return request<ScanReportResponse>(`/scan-reports/${encodeURIComponent(reportId)}`);
}

export function getDomainHistory(domain: string, limit?: number): Promise<DomainHistoryResponse> {
  const query = limit !== undefined ? `?limit=${limit}` : '';
  return request<DomainHistoryResponse>(`/domains/${encodeURIComponent(domain)}/history${query}`);
}

export function submitAbuseReport(input: AbuseReportInput): Promise<AbuseReportResponse> {
  return request<AbuseReportResponse>('/abuse-report', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function getLegalVersions(): Promise<LegalVersionsResponse> {
  return request<LegalVersionsResponse>('/legal/versions');
}
