import { scanFindingSchema } from '@janus/shared';
import { z } from 'zod';

export const tlsScanResultSchema = z.object({
  hostname: z.string(),
  port: z.number().int(),
  scannedAt: z.string(),
  findings: z.array(scanFindingSchema),
});
export type TlsScanResult = z.infer<typeof tlsScanResultSchema>;
