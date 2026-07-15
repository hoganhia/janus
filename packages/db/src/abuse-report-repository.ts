import { getPrismaClient } from './client.js';
import type { AbuseReport } from './generated/prisma/client.js';

export interface CreateAbuseReportInput {
  domain: string;
  reason: string;
  details?: string;
  contact?: string;
}

/**
 * Records an abuse complaint. Deliberately does not upsert/dedupe against `Domain` — see the
 * model's own doc comment in schema.prisma for why this is a flat, unlinked table.
 */
export async function createAbuseReport(input: CreateAbuseReportInput): Promise<AbuseReport> {
  const prisma = getPrismaClient();
  return prisma.abuseReport.create({
    data: {
      domain: input.domain.trim().toLowerCase(),
      reason: input.reason,
      details: input.details ?? null,
      contact: input.contact ?? null,
    },
  });
}
