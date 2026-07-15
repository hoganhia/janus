import { z } from 'zod';

export const scanCheckStatusSchema = z.enum(['pass', 'fail', 'warning']);
export type ScanCheckStatus = z.infer<typeof scanCheckStatusSchema>;

/**
 * A single, self-contained check result from any passive scanner. `explanation` must be
 * readable by a non-technical report viewer; `details` carries the raw supporting data for
 * anyone who wants it, but nothing in the UI should require reading `details` to understand
 * whether something is wrong. `recommendation` is a short, concrete remediation step — present
 * only on `fail`/`warning` findings where there's an actionable fix (not every warning has one,
 * e.g. a DNSSEC lookup that failed to resolve isn't something the target can directly "fix").
 */
export const scanFindingSchema = z.object({
  id: z.string(),
  label: z.string(),
  status: scanCheckStatusSchema,
  explanation: z.string(),
  recommendation: z.string().optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});
export type ScanFinding = z.infer<typeof scanFindingSchema>;
