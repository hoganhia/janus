import { runRetentionSweep } from '@janus/db';

export interface RunDataRetentionSweepResult {
  cutoffDate: string;
  scanReports: number;
  scanConsents: number;
}

function subtractMonths(base: Date, months: number): Date {
  const result = new Date(base);
  result.setMonth(result.getMonth() - months);
  return result;
}

/**
 * Deletes scan records and consent/IP-log records older than `retentionMonths` (default 12 —
 * see RETENTION_MONTHS in @janus/shared). Deliberately does not touch LegalAcceptance — see
 * runRetentionSweep's own doc comment in packages/db/src/legal-repository.ts for why.
 */
export async function runDataRetentionSweep(
  retentionMonths: number,
  now: Date = new Date(),
): Promise<RunDataRetentionSweepResult> {
  const cutoffDate = subtractMonths(now, retentionMonths);
  const result = await runRetentionSweep(cutoffDate);
  return { cutoffDate: cutoffDate.toISOString(), ...result };
}
