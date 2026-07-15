import { scanFindingSchema } from '@janus/shared';
import { z } from 'zod';

export const headersScanResultSchema = z.object({
  url: z.string(),
  scannedAt: z.string(),
  findings: z.array(scanFindingSchema),
});
export type HeadersScanResult = z.infer<typeof headersScanResultSchema>;
