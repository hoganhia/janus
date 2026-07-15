import { FindingRow } from '@/components/results/finding-row';
import { CATEGORY_META, gradeColorClass } from '@/lib/grade';
import type { CategoryScore, ScanFinding } from '@/lib/types';

export function CategoryCard({
  category,
  findings,
}: {
  category: CategoryScore;
  findings: ScanFinding[] | undefined;
}) {
  const meta = CATEGORY_META[category.category];

  return (
    <div className="border-border bg-card rounded-xl border">
      <div className="border-border flex items-center justify-between border-b px-5 py-4">
        <div className="flex items-center gap-2.5">
          <span className="border-border text-muted-foreground rounded border px-1.5 py-0.5 font-mono text-xs">
            {meta.code}
          </span>
          <h2 className="font-medium">{meta.label}</h2>
        </div>
        <span
          className={`font-mono text-lg font-bold ${category.grade !== null ? gradeColorClass(category.grade) : 'text-muted-foreground'}`}
        >
          {category.grade ?? '—'}
        </span>
      </div>

      <div className="divide-border divide-y px-5">
        {!category.applicable || findings === undefined || findings.length === 0 ? (
          <p className="text-muted-foreground py-4 text-sm">
            This category couldn&apos;t be checked for this target.
          </p>
        ) : (
          findings.map((finding) => <FindingRow key={finding.id} finding={finding} />)
        )}
      </div>
    </div>
  );
}
