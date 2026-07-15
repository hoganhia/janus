'use client';

import { ArrowRight, Loader2 } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { ApiError, createScan } from '@/lib/api-client';

/** The API requires a full http(s) URL; users naturally type a bare domain, so add a scheme. */
function withScheme(input: string): string {
  return /^https?:\/\//i.test(input) ? input : `https://${input}`;
}

export function ScanConsole() {
  const router = useRouter();
  const [targetUrl, setTargetUrl] = useState('');
  const [attested, setAttested] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (targetUrl.trim() === '' || !attested || isSubmitting) return;

    const normalized = withScheme(targetUrl.trim());

    setIsSubmitting(true);
    setError(null);
    try {
      const { jobId } = await createScan(normalized, attested);
      router.push(`/scan/${jobId}?target=${encodeURIComponent(normalized)}`);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.body.message
          : 'Could not reach the scan service. Please try again.',
      );
      setIsSubmitting(false);
    }
  }

  return (
    <div className="border-border bg-card mx-auto w-full max-w-xl overflow-hidden rounded-xl border">
      <div className="border-border bg-secondary/40 flex items-center gap-2 border-b px-4 py-2.5">
        <span className="size-2.5 rounded-full bg-[#ff5c5c]/70" />
        <span className="size-2.5 rounded-full bg-[#ffb84d]/70" />
        <span className="size-2.5 rounded-full bg-[#32cd32]/70" />
        <span className="text-muted-foreground ml-2 font-mono text-xs">scan.janus.sh</span>
      </div>

      <form onSubmit={(event) => void handleSubmit(event)} className="p-5">
        <div className="flex items-center gap-2">
          <span className="text-primary font-mono text-sm">$</span>
          <Input
            value={targetUrl}
            onChange={(event) => {
              setTargetUrl(event.target.value);
            }}
            placeholder="yourcompany.com"
            aria-label="Domain to scan"
            className="border-0 bg-transparent px-0 font-mono text-base shadow-none focus-visible:ring-0"
            disabled={isSubmitting}
          />
        </div>

        <Button
          type="submit"
          disabled={targetUrl.trim() === '' || !attested || isSubmitting}
          className="mt-4 w-full"
        >
          {isSubmitting ? (
            <>
              <Loader2 className="animate-spin" /> Running scan…
            </>
          ) : (
            <>
              Run scan <ArrowRight />
            </>
          )}
        </Button>

        {error !== null && <p className="text-destructive mt-3 text-sm">{error}</p>}

        <p className="text-muted-foreground mt-3 font-mono text-xs">
          No login required for a basic scan. Results in seconds.
        </p>

        <label className="mt-4 flex items-start gap-2.5 text-sm">
          <Checkbox
            checked={attested}
            onCheckedChange={(checked) => {
              setAttested(checked);
            }}
            className="mt-0.5"
          />
          <span className="text-muted-foreground">
            I own this domain or have authorization to assess it, per the{' '}
            <Link href="/acceptable-use" className="underline underline-offset-2">
              Acceptable Use Policy
            </Link>
            .
          </span>
        </label>
      </form>
    </div>
  );
}
