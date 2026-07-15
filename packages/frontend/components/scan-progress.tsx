'use client';

import { Loader2, TriangleAlert } from 'lucide-react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { useScanStatus } from '@/hooks/use-scan-status';

export function ScanProgress({ jobId }: { jobId: string }) {
  const router = useRouter();
  const target = useSearchParams().get('target');
  const { status, error, isDone } = useScanStatus(jobId);

  useEffect(() => {
    if (isDone && status?.status === 'completed' && status.result !== undefined) {
      router.replace(`/reports/${status.result.scanReportId}`);
    }
  }, [isDone, status, router]);

  const failed = status?.status === 'failed' || error !== undefined;

  return (
    <main className="mx-auto flex max-w-xl flex-col items-center px-6 py-24 text-center">
      <div className="border-border bg-card w-full overflow-hidden rounded-xl border">
        <div className="border-border bg-secondary/40 flex items-center gap-2 border-b px-4 py-2.5">
          <span className="size-2.5 rounded-full bg-[#ff5c5c]/70" />
          <span className="size-2.5 rounded-full bg-[#ffb84d]/70" />
          <span className="size-2.5 rounded-full bg-[#32cd32]/70" />
          <span className="text-muted-foreground ml-2 font-mono text-xs">scan.perimeter.sh</span>
        </div>

        <div className="p-8">
          {failed ? (
            <>
              <TriangleAlert className="text-destructive mx-auto size-8" />
              <p className="mt-4 font-medium">Scan failed</p>
              <p className="text-muted-foreground mt-2 text-sm">
                {status?.failedReason ??
                  'Something went wrong reaching this endpoint. Please try again.'}
              </p>
              <Button render={<Link href="/" />} className="mt-6">
                Run another scan
              </Button>
            </>
          ) : (
            <>
              <Loader2 className="text-primary mx-auto size-8 animate-spin" />
              <p className="mt-4 font-mono text-sm">
                Scanning {target ?? 'target'}
                <span className="animate-pulse">…</span>
              </p>
              <p className="text-muted-foreground mt-2 text-xs">
                Checking transport security, headers, DNS &amp; email security, and software
                hygiene.
              </p>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
