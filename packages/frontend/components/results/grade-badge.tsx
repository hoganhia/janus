import { gradeColorClass } from '@/lib/grade';
import type { LetterGrade } from '@/lib/types';

export function GradeBadge({ grade, size = 'lg' }: { grade: LetterGrade; size?: 'lg' | 'sm' }) {
  const dimensions = size === 'lg' ? 'size-20 text-3xl' : 'size-9 text-sm';

  return (
    <div
      className={`border-primary/40 bg-primary/10 shadow-primary/20 flex shrink-0 items-center justify-center rounded-full border-2 font-mono font-bold shadow-[0_0_24px] ${dimensions} ${gradeColorClass(grade)}`}
    >
      {grade}
    </div>
  );
}
