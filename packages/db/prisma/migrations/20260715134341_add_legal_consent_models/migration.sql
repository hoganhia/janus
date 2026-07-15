-- CreateEnum
CREATE TYPE "LegalDocumentType" AS ENUM ('TERMS_OF_SERVICE', 'PRIVACY_POLICY', 'ACCEPTABLE_USE_POLICY');

-- CreateTable
CREATE TABLE "LegalVersion" (
    "id" TEXT NOT NULL,
    "documentType" "LegalDocumentType" NOT NULL,
    "version" TEXT NOT NULL,
    "changeNote" TEXT,
    "effectiveAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LegalVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanConsent" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "requesterIp" TEXT NOT NULL,
    "targetDomain" TEXT NOT NULL,
    "attestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "acceptableUseVersionId" TEXT NOT NULL,

    CONSTRAINT "ScanConsent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LegalAcceptance" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "documentType" "LegalDocumentType" NOT NULL,
    "legalVersionId" TEXT NOT NULL,
    "acceptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT NOT NULL,

    CONSTRAINT "LegalAcceptance_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "LegalVersion_documentType_effectiveAt_idx" ON "LegalVersion"("documentType", "effectiveAt");

-- CreateIndex
CREATE UNIQUE INDEX "LegalVersion_documentType_version_key" ON "LegalVersion"("documentType", "version");

-- CreateIndex
CREATE INDEX "ScanConsent_targetDomain_idx" ON "ScanConsent"("targetDomain");

-- CreateIndex
CREATE INDEX "ScanConsent_attestedAt_idx" ON "ScanConsent"("attestedAt");

-- CreateIndex
CREATE INDEX "LegalAcceptance_userId_idx" ON "LegalAcceptance"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "LegalAcceptance_userId_documentType_legalVersionId_key" ON "LegalAcceptance"("userId", "documentType", "legalVersionId");

-- AddForeignKey
ALTER TABLE "ScanConsent" ADD CONSTRAINT "ScanConsent_acceptableUseVersionId_fkey" FOREIGN KEY ("acceptableUseVersionId") REFERENCES "LegalVersion"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LegalAcceptance" ADD CONSTRAINT "LegalAcceptance_legalVersionId_fkey" FOREIGN KEY ("legalVersionId") REFERENCES "LegalVersion"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Seed the initial version row for each legal document, so ScanConsent/LegalAcceptance have
-- something to reference from the moment this migration runs, in every environment (dev, CI,
-- prod) — see getCurrentLegalVersion in packages/db/src/legal-repository.ts. Every document's
-- actual text is placeholder-only pending legal review — see LEGAL_REVIEW.md at the repo root.
INSERT INTO "LegalVersion" ("id", "documentType", "version", "changeNote", "effectiveAt") VALUES
  ('legalver_tos_v1', 'TERMS_OF_SERVICE', '1.0.0-placeholder', 'Initial placeholder text pending legal review.', CURRENT_TIMESTAMP),
  ('legalver_privacy_v1', 'PRIVACY_POLICY', '1.0.0-placeholder', 'Initial placeholder text pending legal review.', CURRENT_TIMESTAMP),
  ('legalver_aup_v1', 'ACCEPTABLE_USE_POLICY', '1.0.0-placeholder', 'Initial placeholder text pending legal review.', CURRENT_TIMESTAMP);
