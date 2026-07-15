-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateTable
CREATE TABLE "Cve" (
    "id" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "baseScore" DOUBLE PRECISION NOT NULL,
    "published" TIMESTAMP(3) NOT NULL,
    "lastModified" TIMESTAMP(3) NOT NULL,
    "syncedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Cve_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CveAffectedProduct" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "productKey" TEXT NOT NULL,
    "versionStartIncluding" TEXT,
    "versionStartExcluding" TEXT,
    "versionEndIncluding" TEXT,
    "versionEndExcluding" TEXT,
    "exactVersion" TEXT,

    CONSTRAINT "CveAffectedProduct_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CveSyncState" (
    "productKey" TEXT NOT NULL,
    "lastSyncedAt" TIMESTAMP(3),
    "lastStatus" TEXT,
    "lastError" TEXT,

    CONSTRAINT "CveSyncState_pkey" PRIMARY KEY ("productKey")
);

-- CreateIndex
CREATE INDEX "Cve_severity_published_idx" ON "Cve"("severity", "published");

-- CreateIndex
CREATE INDEX "CveAffectedProduct_productKey_idx" ON "CveAffectedProduct"("productKey");

-- AddForeignKey
ALTER TABLE "CveAffectedProduct" ADD CONSTRAINT "CveAffectedProduct_cveId_fkey" FOREIGN KEY ("cveId") REFERENCES "Cve"("id") ON DELETE CASCADE ON UPDATE CASCADE;
