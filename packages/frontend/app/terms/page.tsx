import { ArrowLeft } from 'lucide-react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { LegalReviewBanner } from '@/components/legal-review-banner';
import { LegalVersionBadge } from '@/components/legal-version-badge';

export const metadata: Metadata = {
  title: 'Terms of Service — Janus',
};

export default function TermsPage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <Link
        href="/"
        className="text-muted-foreground hover:text-foreground mb-10 inline-flex items-center gap-1.5 font-mono text-sm"
      >
        <ArrowLeft className="size-4" />
        Back to scan
      </Link>

      <h1 className="text-2xl font-semibold tracking-tight">Terms of Service</h1>
      <div className="mt-2">
        <LegalVersionBadge documentType="TERMS_OF_SERVICE" />
      </div>

      <div className="mt-6">
        <LegalReviewBanner />
      </div>

      <div className="text-muted-foreground space-y-6 text-sm leading-relaxed">
        <section>
          <h2 className="text-foreground font-medium">1. Acceptance of terms</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] By using Janus, you agree to these Terms of
            Service, the Acceptable Use Policy, and the Privacy Policy. If you do not agree, do not
            use the service.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">2. Description of service</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] Janus performs passive, read-only checks against
            publicly reachable endpoints of a domain you submit (TLS configuration, HTTP response
            headers, DNS records, and publicly visible software identifiers) and produces a scored
            report. See /methodology for what is and is not checked.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">3. No compliance certification</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] Scan results are an external, point-in-time
            security signal only. They are not a penetration test, a compliance certification (e.g.
            SOC 2, PCI DSS, ISO 27001), and do not constitute legal, security, or compliance advice.
            Passing every check does not mean a target meets any regulatory or contractual standard.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">
            4. Limitation of liability for scan accuracy
          </h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] The service is provided &quot;as is&quot; without
            warranties of any kind. We do not warrant that scan results are complete, accurate, or
            current, or that they identify every security issue affecting a target. To the maximum
            extent permitted by law, we disclaim liability for any decision made, or action taken
            (or not taken), in reliance on a scan result.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">
            5. Authorization required to scan a domain
          </h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] You may only submit a domain for scanning if you
            own it or have express authorization from its owner to assess it. Using this service to
            scan a domain without authorization is prohibited — see the Acceptable Use Policy for
            the full policy and consequences of violation.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">6. Suspension and termination</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] We may suspend or terminate access to the service,
            without notice, for conduct that violates these terms or the Acceptable Use Policy, or
            that we reasonably believe is harmful to the service, other users, or third parties.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">7. Changes to these terms</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] We may update these terms from time to time.
            Material changes will be reflected in the version and effective date shown at the top of
            this page — see the CHANGELOG-style version history our systems keep for exactly what a
            given account agreed to and when.
          </p>
        </section>
      </div>
    </main>
  );
}
