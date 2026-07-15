import type { LetterGrade, ReportCategory } from './types';

export const CATEGORY_META: Record<ReportCategory, { code: string; label: string }> = {
  transportSecurity: { code: 'TLS', label: 'Transport Security' },
  headers: { code: 'HDR', label: 'HTTP Security Headers' },
  emailDnsSecurity: { code: 'DNS', label: 'DNS & Email Security' },
  softwareHygiene: { code: 'SFT', label: 'Software Hygiene' },
};

const GRADE_COLOR_CLASS: Record<LetterGrade, string> = {
  A: 'text-primary',
  B: 'text-primary',
  C: 'text-warning',
  D: 'text-destructive',
  F: 'text-destructive',
};

export function gradeColorClass(grade: LetterGrade): string {
  return GRADE_COLOR_CLASS[grade];
}
