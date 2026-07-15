import useSWR from 'swr';
import { getLegalVersions } from '@/lib/api-client';

export function useLegalVersions() {
  const { data, error, isLoading } = useSWR('/legal/versions', getLegalVersions);
  return { versions: data, isLoading, error };
}
