import { ArrowLeft } from 'lucide-react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { LegalReviewBanner } from '@/components/legal-review-banner';
import { LegalVersionBadge } from '@/components/legal-version-badge';

export const metadata: Metadata = {
  title: 'Acceptable Use Policy — Perimeter',
};

export default function AcceptableUsePage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <Link
        href="/"
        className="text-muted-foreground hover:text-foreground mb-10 inline-flex items-center gap-1.5 font-mono text-sm"
      >
        <ArrowLeft className="size-4" />
        Back to scan
      </Link>

      <h1 className="text-2xl font-semibold tracking-tight">Acceptable Use Policy</h1>
      <div className="mt-2">
        <LegalVersionBadge documentType="ACCEPTABLE_USE_POLICY" />
      </div>

      <div className="mt-6">
        <LegalReviewBanner />
      </div>

      <div className="text-muted-foreground space-y-6 text-sm leading-relaxed">
        <section>
          <h2 className="text-foreground font-medium">1. Purpose</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] This policy exists so a passive external security
            scanner does not itself become a tool for unauthorized reconnaissance. Every scan
            submission requires you to affirmatively confirm you own the target domain or have
            authorization to assess it — see the attestation checkbox on the scan form, and the
            audit trail we keep of that attestation.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">2. Prohibited uses</h2>
          <ul className="mt-2 list-disc space-y-2 pl-5">
            <li>
              [PLACEHOLDER — REQUIRES LEGAL REVIEW] Submitting a domain for scanning that you do not
              own and do not have authorization to assess.
            </li>
            <li>
              [PLACEHOLDER — REQUIRES LEGAL REVIEW] Attempting to circumvent a domain&apos;s opt-out
              signal (the <code className="bg-card rounded px-1 py-0.5">_perimeter-opt-out</code>{' '}
              DNS TXT record) or rate limits.
            </li>
            <li>
              [PLACEHOLDER — REQUIRES LEGAL REVIEW] Using scan results to harass, extort, or
              otherwise cause harm to a domain&apos;s owner or operator.
            </li>
            <li>
              [PLACEHOLDER — REQUIRES LEGAL REVIEW] Automating submissions in a way designed to
              circumvent per-IP rate limits or place excessive load on the service.
            </li>
          </ul>
        </section>

        <section>
          <h2 className="text-foreground font-medium">3. Consequences of violation</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] Violating this policy may result in suspension or
            termination of access, and — depending on severity — a report to relevant authorities.
            See the Terms of Service&apos;s suspension and termination section.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">4. Reporting a concern</h2>
          <p className="mt-2">
            If you believe this scanner has been used against your domain without authorization, or
            its behavior toward your domain is otherwise a problem, you can block it immediately via
            the DNS opt-out record, or tell us directly — see{' '}
            <Link href="/about-this-scanner" className="underline underline-offset-2">
              /about-this-scanner
            </Link>{' '}
            for both options.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">5. Changes to this policy</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] We may update this policy from time to time.
            Material changes will be reflected in the version and effective date shown at the top of
            this page.
          </p>
        </section>
      </div>
    </main>
  );
}
