-- CreateTable
CREATE TABLE "AbuseReport" (
    "id" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "details" TEXT,
    "contact" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AbuseReport_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AbuseReport_domain_idx" ON "AbuseReport"("domain");
