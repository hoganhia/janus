'use client';

import { ArrowLeft, TrendingUp } from 'lucide-react';
import Link from 'next/link';
import { CategoryCard } from '@/components/results/category-card';
import { GradeBadge } from '@/components/results/grade-badge';
import { Disclaimer } from '@/components/disclaimer';
import { Skeleton } from '@/components/ui/skeleton';
import { useScanReport } from '@/hooks/use-scan-report';
import { ApiError } from '@/lib/api-client';
import { CATEGORY_TO_RESULTS_KEY } from '@/lib/types';

export function ScanReportView({ reportId }: { reportId: string }) {
  const { report, error, isLoading } = useScanReport(reportId);

  if (isLoading) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-16">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="mt-8 h-24 w-full" />
        <Skeleton className="mt-6 h-40 w-full" />
        <Skeleton className="mt-4 h-40 w-full" />
      </main>
    );
  }

  if (error !== undefined || report === undefined) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-16 text-center">
        <p className="font-medium">
          {error instanceof ApiError ? error.body.message : 'This scan report could not be found.'}
        </p>
        <Link href="/" className="text-primary mt-4 inline-block text-sm">
          Run another scan
        </Link>
      </main>
    );
  }

  const { computedScore, rawResults } = report;

  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <Link
        href="/"
        className="text-muted-foreground hover:text-foreground mb-10 inline-flex items-center gap-1.5 font-mono text-sm"
      >
        <ArrowLeft className="size-4" />
        Run another scan
      </Link>

      <div className="flex items-start justify-between gap-6">
        <div>
          <p className="text-muted-foreground font-mono text-sm">{report.domain}</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">Scan results</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            {new Date(report.scannedAt).toLocaleString()}
          </p>
          <Link
            href={`/domains/${report.domain}`}
            className="text-primary mt-3 inline-flex items-center gap-1.5 text-sm"
          >
            <TrendingUp className="size-3.5" />
            View history for this domain
          </Link>
        </div>
        <GradeBadge grade={report.overallGrade} />
      </div>

      <div className="mt-8">
        <Disclaimer />
      </div>

      <div className="mt-8 space-y-6">
        {computedScore.categories.map((category) => (
          <CategoryCard
            key={category.category}
            category={category}
            findings={rawResults[CATEGORY_TO_RESULTS_KEY[category.category]]?.findings}
          />
        ))}
      </div>
    </main>
  );
}
