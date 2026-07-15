import { scanFindingSchema } from '@janus/shared';
import { z } from 'zod';

export const fingerprintScanResultSchema = z.object({
  url: z.string(),
  scannedAt: z.string(),
  /** Always present: version detection here is probabilistic — parsed from headers and
   * static files a server voluntarily discloses, which can be spoofed, outdated, or simply
   * absent. Findings are signals to verify, not certainties. */
  caveat: z.string(),
  findings: z.array(scanFindingSchema),
});
export type FingerprintScanResult = z.infer<typeof fingerprintScanResultSchema>;
