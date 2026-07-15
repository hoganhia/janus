'use client';

import { useLegalVersions } from '@/hooks/use-legal-versions';
import type { LegalDocumentType } from '@/lib/types';

export function LegalVersionBadge({ documentType }: { documentType: LegalDocumentType }) {
  const { versions, isLoading } = useLegalVersions();

  if (isLoading || versions === undefined) {
    return <p className="text-muted-foreground font-mono text-xs">Loading version…</p>;
  }

  const info = versions[documentType];
  return (
    <p className="text-muted-foreground font-mono text-xs">
      Version {info.version} — effective {new Date(info.effectiveAt).toLocaleDateString()}
    </p>
  );
}
