'use client';

import Link from 'next/link';
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { GradeBadge } from '@/components/results/grade-badge';
import { Skeleton } from '@/components/ui/skeleton';
import { useDomainHistory } from '@/hooks/use-domain-history';

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function DomainHistoryView({ domain }: { domain: string }) {
  const { history, isLoading, error } = useDomainHistory(domain);

  if (isLoading) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-16">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="mt-8 h-56 w-full" />
      </main>
    );
  }

  if (error !== undefined || history === undefined) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-16 text-center">
        <p className="font-medium">Could not load history for this domain.</p>
        <Link href="/" className="text-primary mt-4 inline-block text-sm">
          Run a scan
        </Link>
      </main>
    );
  }

  const chronological = [...history.scans].reverse();
  const chartData = chronological.map((scan) => ({
    date: formatDate(scan.scannedAt),
    score: scan.overallScore,
  }));

  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <p className="text-muted-foreground font-mono text-sm">{history.domain}</p>
      <h1 className="mt-1 text-2xl font-semibold tracking-tight">Scan history</h1>

      {history.scans.length === 0 ? (
        <p className="text-muted-foreground mt-8 text-sm">
          No scans recorded for this domain yet. <Link href="/">Run one now</Link>.
        </p>
      ) : (
        <>
          <div className="border-border bg-card mt-8 h-64 rounded-xl border p-4">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis
                  dataKey="date"
                  stroke="var(--muted-foreground)"
                  fontSize={12}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  stroke="var(--muted-foreground)"
                  fontSize={12}
                  tickLine={false}
                  width={30}
                />
                <Tooltip
                  contentStyle={{
                    background: 'var(--card)',
                    border: '1px solid var(--border)',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  labelStyle={{ color: 'var(--foreground)' }}
                />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="var(--primary)"
                  strokeWidth={2}
                  dot={{ fill: 'var(--primary)', r: 3 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="border-border divide-border mt-8 divide-y rounded-xl border">
            {history.scans.map((scan) => (
              <Link
                key={scan.id}
                href={`/reports/${scan.id}`}
                className="hover:bg-secondary/40 flex items-center justify-between gap-4 px-5 py-4"
              >
                <div>
                  <p className="text-sm font-medium">{new Date(scan.scannedAt).toLocaleString()}</p>
                  <p className="text-muted-foreground text-sm">Score: {scan.overallScore}</p>
                </div>
                <GradeBadge grade={scan.overallGrade} size="sm" />
              </Link>
            ))}
          </div>
        </>
      )}
    </main>
  );
}
