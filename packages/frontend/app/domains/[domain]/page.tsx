import { DomainHistoryView } from '@/components/domain-history-view';

export default async function DomainHistoryPage({
  params,
}: {
  params: Promise<{ domain: string }>;
}) {
  const { domain } = await params;
  return <DomainHistoryView domain={domain} />;
}
