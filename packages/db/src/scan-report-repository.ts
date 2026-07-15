import { getPrismaClient } from './client.js';
import type { Domain, LetterGrade, Prisma, ScanReport } from './generated/prisma/client.js';

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase();
}

/**
 * Finds the `Domain` row for `domain`, creating it with `UNVERIFIED` status if it doesn't exist
 * yet. Domain names are normalized (trimmed, lowercased) before lookup/creation — DNS names are
 * case-insensitive, so without this "Example.com" and "example.com" would otherwise become two
 * separate rows with separate scan histories.
 */
export async function findOrCreateDomain(domain: string): Promise<Domain> {
  const normalized = normalizeDomain(domain);
  const prisma = getPrismaClient();
  return prisma.domain.upsert({
    where: { domain: normalized },
    create: { domain: normalized },
    update: {},
  });
}

export interface RecordScanReportInput {
  domain: string;
  scannedAt: Date;
  /** The `ScanResults` object passed into `scoreReport()` (from `@janus/scanners`). */
  rawResults: Prisma.InputJsonValue;
  /** The full `ScoreReport` object `scoreReport()` returned. */
  computedScore: Prisma.InputJsonValue;
  overallGrade: LetterGrade;
  overallScore: number;
}

/**
 * Records one versioned scan report for `domain`, creating the `Domain` row on first scan.
 * Every call creates a new row rather than updating an existing one — each scan is its own
 * point in that domain's history, which is what lets `getScanReportHistory` show trends over
 * time rather than only ever the latest result.
 */
export async function recordScanReport(input: RecordScanReportInput): Promise<ScanReport> {
  const domainRow = await findOrCreateDomain(input.domain);
  const prisma = getPrismaClient();
  return prisma.scanReport.create({
    data: {
      domainId: domainRow.id,
      scannedAt: input.scannedAt,
      rawResults: input.rawResults,
      computedScore: input.computedScore,
      overallGrade: input.overallGrade,
      overallScore: input.overallScore,
    },
  });
}

export interface ScanReportWithDomain extends ScanReport {
  domain: Domain;
}

/**
 * Looks up one scan report by its own ID, including the `Domain` row it belongs to (the
 * frontend results page needs the domain name to display/link back to, and `ScanReport` itself
 * only stores `domainId`). Public by design, same as `getScanReportHistory` — a completed
 * scan's results aren't sensitive, and the ID is an unguessable cuid, not a sequential one.
 * Unlike a BullMQ job's status (gone after ~24h, see enqueueScanJob), this is the permanent
 * record: the same ID keeps working for as long as the report exists, which is what lets the
 * historical-trend view link into any past scan, not just a freshly completed one.
 */
export async function getScanReportById(id: string): Promise<ScanReportWithDomain | null> {
  const prisma = getPrismaClient();
  return prisma.scanReport.findUnique({ where: { id }, include: { domain: true } });
}

export interface ScanReportHistoryOptions {
  /** Default: 20. */
  limit?: number;
}

const DEFAULT_HISTORY_LIMIT = 20;

/**
 * Most-recent-first scan report history for a domain — the basis for a trend chart. Returns an
 * empty array (not an error) for a domain that doesn't exist or has never been scanned, since
 * "no history yet" isn't a failure case for a caller building a chart.
 */
export async function getScanReportHistory(
  domain: string,
  options: ScanReportHistoryOptions = {},
): Promise<ScanReport[]> {
  const normalized = normalizeDomain(domain);
  const prisma = getPrismaClient();
  const domainRow = await prisma.domain.findUnique({ where: { domain: normalized } });
  if (domainRow === null) return [];

  return prisma.scanReport.findMany({
    where: { domainId: domainRow.id },
    orderBy: { scannedAt: 'desc' },
    take: options.limit ?? DEFAULT_HISTORY_LIMIT,
  });
}
