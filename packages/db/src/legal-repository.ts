import { getPrismaClient } from './client.js';
import type {
  LegalAcceptance,
  LegalDocumentType,
  LegalVersion,
  ScanConsent,
} from './generated/prisma/client.js';

/**
 * The "current" version of a legal document is whichever row has the latest `effectiveAt` for
 * that `documentType` — see LegalVersion's own doc comment in schema.prisma. Throws if none
 * exists, which should never happen outside a broken deployment (every document type is seeded
 * with an initial row directly in the migration that creates this table).
 */
export async function getCurrentLegalVersion(
  documentType: LegalDocumentType,
): Promise<LegalVersion> {
  const prisma = getPrismaClient();
  const version = await prisma.legalVersion.findFirst({
    where: { documentType },
    orderBy: { effectiveAt: 'desc' },
  });
  if (version === null) {
    throw new Error(`No LegalVersion row exists for ${documentType} — check migrations ran.`);
  }
  return version;
}

export interface RecordScanConsentInput {
  userId?: string | null;
  requesterIp: string;
  targetDomain: string;
}

/**
 * Records one scan submission's authorization attestation — see ScanConsent's doc comment in
 * schema.prisma for why `userId` is (for now) always null. Always attests against the
 * *current* Acceptable Use Policy version, looked up fresh on every call rather than cached, so
 * a version bump takes effect on the very next scan.
 */
export async function recordScanConsent(input: RecordScanConsentInput): Promise<ScanConsent> {
  const prisma = getPrismaClient();
  const aupVersion = await getCurrentLegalVersion('ACCEPTABLE_USE_POLICY');
  return prisma.scanConsent.create({
    data: {
      userId: input.userId ?? null,
      requesterIp: input.requesterIp,
      targetDomain: input.targetDomain,
      acceptableUseVersionId: aupVersion.id,
    },
  });
}

export interface RecordLegalAcceptanceInput {
  userId: string;
  documentType: LegalDocumentType;
  ipAddress: string;
}

/**
 * Records that `userId` has agreed to the *current* version of `documentType`. Idempotent —
 * accepting the same (user, document, version) twice just returns the existing row rather than
 * erroring, since a double-click on "I agree" shouldn't be a client-visible failure.
 */
export async function recordLegalAcceptance(
  input: RecordLegalAcceptanceInput,
): Promise<LegalAcceptance> {
  const prisma = getPrismaClient();
  const version = await getCurrentLegalVersion(input.documentType);
  return prisma.legalAcceptance.upsert({
    where: {
      userId_documentType_legalVersionId: {
        userId: input.userId,
        documentType: input.documentType,
        legalVersionId: version.id,
      },
    },
    create: {
      userId: input.userId,
      documentType: input.documentType,
      legalVersionId: version.id,
      ipAddress: input.ipAddress,
    },
    update: {},
  });
}

/** Whether `userId` has accepted the *current* version of `documentType` — not just some past version. */
export async function hasAcceptedLatestLegalVersion(
  userId: string,
  documentType: LegalDocumentType,
): Promise<boolean> {
  const prisma = getPrismaClient();
  const version = await getCurrentLegalVersion(documentType);
  const acceptance = await prisma.legalAcceptance.findUnique({
    where: {
      userId_documentType_legalVersionId: {
        userId,
        documentType,
        legalVersionId: version.id,
      },
    },
  });
  return acceptance !== null;
}

export interface DeleteUserLegalDataResult {
  scanConsents: number;
  legalAcceptances: number;
}

/**
 * "Delete my account and data" — deletes only rows that are actually about the requesting user
 * (their own consent/acceptance history). Deliberately does NOT touch Domain/ScanReport: those
 * describe a third-party target's public security posture, not personal data about this user —
 * see the user-data-vs-third-party-data distinction in the privacy policy. See LEGAL_REVIEW.md
 * for why this scoping decision itself still needs a lawyer's sign-off before launch.
 */
export async function deleteUserLegalData(userId: string): Promise<DeleteUserLegalDataResult> {
  const prisma = getPrismaClient();
  const [scanConsents, legalAcceptances] = await prisma.$transaction([
    prisma.scanConsent.deleteMany({ where: { userId } }),
    prisma.legalAcceptance.deleteMany({ where: { userId } }),
  ]);
  return { scanConsents: scanConsents.count, legalAcceptances: legalAcceptances.count };
}

export interface RetentionSweepResult {
  scanReports: number;
  scanConsents: number;
}

/**
 * Deletes scan records and consent/IP-log records older than `cutoffDate` — see the scheduled
 * job in packages/workers/src/data-retention. Deliberately leaves LegalAcceptance alone: proof
 * that a still-active account agreed to the current Terms/AUP needs to survive as long as the
 * account does, not expire on a fixed clock.
 */
export async function runRetentionSweep(cutoffDate: Date): Promise<RetentionSweepResult> {
  const prisma = getPrismaClient();
  const [scanReports, scanConsents] = await prisma.$transaction([
    prisma.scanReport.deleteMany({ where: { scannedAt: { lt: cutoffDate } } }),
    prisma.scanConsent.deleteMany({ where: { attestedAt: { lt: cutoffDate } } }),
  ]);
  return { scanReports: scanReports.count, scanConsents: scanConsents.count };
}
