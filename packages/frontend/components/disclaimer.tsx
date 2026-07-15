import { TriangleAlert } from 'lucide-react';
import Link from 'next/link';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

/**
 * Shown on every page that displays scan results — this is a legal/trust requirement, not just
 * a UI nicety, so it isn't something a page should be able to accidentally omit.
 */
export function Disclaimer({ className }: { className?: string }) {
  return (
    <Alert
      className={`border-warning/40 bg-warning/5 [&_svg]:text-warning ${className ?? ''}`}
      data-slot="disclaimer"
    >
      <TriangleAlert />
      <AlertTitle>This is an external security signal, not a compliance certification.</AlertTitle>
      <AlertDescription>
        Perimeter only checks what&apos;s publicly visible from the outside — it can&apos;t see your
        internal controls, and passing every check here doesn&apos;t mean you meet any regulatory or
        contractual standard. <Link href="/methodology">Read how scans and grades work</Link>.
      </AlertDescription>
    </Alert>
  );
}
