import { ScanProgress } from '@/components/scan-progress';

export default async function ScanStatusPage({ params }: { params: Promise<{ jobId: string }> }) {
  const { jobId } = await params;
  return <ScanProgress jobId={jobId} />;
}
