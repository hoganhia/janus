import useSWR from 'swr';
import { getScanReport } from '@/lib/api-client';

export function useScanReport(reportId: string | undefined) {
  const { data, error, isLoading } = useSWR(
    reportId !== undefined ? `/scan-reports/${reportId}` : null,
    () => getScanReport(reportId as string),
  );

  return { report: data, isLoading, error };
}
