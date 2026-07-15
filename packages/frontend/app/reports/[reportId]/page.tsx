import { ScanReportView } from '@/components/scan-report-view';

export default async function ScanReportPage({
  params,
}: {
  params: Promise<{ reportId: string }>;
}) {
  const { reportId } = await params;
  return <ScanReportView reportId={reportId} />;
}
