import useSWR from 'swr';
import { getDomainHistory } from '@/lib/api-client';

export function useDomainHistory(domain: string | undefined) {
  const { data, error, isLoading } = useSWR(
    domain !== undefined ? `/domains/${domain}/history` : null,
    () => getDomainHistory(domain as string),
  );

  return { history: data, isLoading, error };
}
