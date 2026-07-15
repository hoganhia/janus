import { scanFindingSchema } from '@janus/shared';
import { z } from 'zod';

export const dnsScanResultSchema = z.object({
  domain: z.string(),
  scannedAt: z.string(),
  findings: z.array(scanFindingSchema),
});
export type DnsScanResult = z.infer<typeof dnsScanResultSchema>;
