import useSWR from 'swr';
import { getScanStatus } from '@/lib/api-client';
import type { ScanStatusResponse } from '@/lib/types';

const POLL_INTERVAL_MS = 2000;
const TERMINAL_STATUSES = new Set(['completed', 'failed']);

/** Polls GET /scans/:jobId until the job reaches a terminal (completed/failed) state. */
export function useScanStatus(jobId: string | undefined) {
  const { data, error, isLoading } = useSWR<ScanStatusResponse>(
    jobId !== undefined ? `/scans/${jobId}` : null,
    () => getScanStatus(jobId as string),
    {
      refreshInterval: (latest) =>
        latest !== undefined && TERMINAL_STATUSES.has(latest.status) ? 0 : POLL_INTERVAL_MS,
      revalidateOnFocus: false,
    },
  );

  return {
    status: data,
    isLoading,
    error,
    isDone: data !== undefined && TERMINAL_STATUSES.has(data.status),
  };
}
