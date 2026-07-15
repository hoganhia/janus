import { Check, TriangleAlert, Wrench, X } from 'lucide-react';
import type { ScanFinding } from '@/lib/types';

const STATUS_META = {
  pass: { icon: Check, className: 'bg-primary/15 text-primary' },
  warning: { icon: TriangleAlert, className: 'bg-warning/15 text-warning' },
  fail: { icon: X, className: 'bg-destructive/15 text-destructive' },
} as const;

export function FindingRow({ finding }: { finding: ScanFinding }) {
  const { icon: Icon, className } = STATUS_META[finding.status];

  return (
    <div className="flex items-start gap-3 py-3">
      <span className={`flex size-6 shrink-0 items-center justify-center rounded-md ${className}`}>
        <Icon className="size-3.5" />
      </span>
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-medium">{finding.label}</p>
          <span className="border-border text-muted-foreground rounded border px-1 py-0.5 font-mono text-[10px]">
            {finding.id}
          </span>
        </div>
        <p className="text-muted-foreground mt-1 text-sm leading-relaxed">{finding.explanation}</p>
        {finding.recommendation !== undefined && (
          <div className="border-border bg-secondary/40 mt-2 flex items-start gap-2 rounded-md border px-2.5 py-2">
            <Wrench className="text-muted-foreground mt-0.5 size-3.5 shrink-0" />
            <p className="text-foreground text-sm leading-relaxed">{finding.recommendation}</p>
          </div>
        )}
      </div>
    </div>
  );
}
