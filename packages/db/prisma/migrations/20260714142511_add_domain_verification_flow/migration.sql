-- CreateEnum
CREATE TYPE "DomainVerificationMethod" AS ENUM ('DNS_TXT', 'WELL_KNOWN_FILE');

-- CreateEnum
CREATE TYPE "ScanTier" AS ENUM ('PASSIVE', 'AUTHENTICATED');

-- AlterEnum
ALTER TYPE "DomainVerificationStatus" ADD VALUE 'EXPIRED';

-- AlterTable
ALTER TABLE "Domain" ADD COLUMN     "scanTier" "ScanTier" NOT NULL DEFAULT 'PASSIVE',
ADD COLUMN     "verificationExpiresAt" TIMESTAMP(3),
ADD COLUMN     "verificationMethod" "DomainVerificationMethod";

-- CreateIndex
CREATE INDEX "Domain_verificationStatus_verificationExpiresAt_idx" ON "Domain"("verificationStatus", "verificationExpiresAt");
