import { ArrowLeft } from 'lucide-react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { LegalReviewBanner } from '@/components/legal-review-banner';
import { LegalVersionBadge } from '@/components/legal-version-badge';

export const metadata: Metadata = {
  title: 'Privacy Policy — Janus',
};

export default function PrivacyPage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <Link
        href="/"
        className="text-muted-foreground hover:text-foreground mb-10 inline-flex items-center gap-1.5 font-mono text-sm"
      >
        <ArrowLeft className="size-4" />
        Back to scan
      </Link>

      <h1 className="text-2xl font-semibold tracking-tight">Privacy Policy</h1>
      <div className="mt-2">
        <LegalVersionBadge documentType="PRIVACY_POLICY" />
      </div>

      <div className="mt-6">
        <LegalReviewBanner />
      </div>

      <div className="text-muted-foreground space-y-6 text-sm leading-relaxed">
        <section>
          <h2 className="text-foreground font-medium">1. Two kinds of data, two different rules</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] This policy treats two categories of data
            differently, because they have different legal bases and different retention needs:
          </p>
          <ul className="mt-2 list-disc space-y-2 pl-5">
            <li>
              <span className="text-foreground font-medium">Data about our users</span> — an
              account&apos;s Terms/Acceptable-Use acceptance record (timestamp and version agreed
              to), and, if a scan is ever submitted while signed in, the requester&apos;s IP address
              tied to that submission. This is personal data about you, and is what a &quot;delete
              my account and data&quot; request removes.
            </li>
            <li>
              <span className="text-foreground font-medium">
                Data about scanned third-party domains
              </span>{' '}
              — the scan results themselves (TLS configuration, response headers, DNS records,
              publicly visible software identifiers) describe the public-facing posture of a domain,
              not personal data about the person who requested the scan. This data is not deleted by
              any individual requester&apos;s account-deletion request, since it belongs to — and
              may be relied on by — anyone who has scanned or looked up that domain.
            </li>
          </ul>
        </section>

        <section>
          <h2 className="text-foreground font-medium">2. What we collect</h2>
          <ul className="mt-2 list-disc space-y-2 pl-5">
            <li>The domain you submit for scanning, and the resulting scan report.</li>
            <li>
              The IP address and timestamp of each scan submission, and your attestation that you
              own or are authorized to assess the target domain — kept as an audit trail in case a
              scanned domain&apos;s owner ever disputes being scanned.
            </li>
            <li>
              If you sign in for account-tied actions (domain-ownership verification): your Clerk
              account ID, and your Terms of Service / Acceptable Use Policy acceptance record.
            </li>
          </ul>
        </section>

        <section>
          <h2 className="text-foreground font-medium">3. Data retention</h2>
          <p className="mt-2">
            Scan records and the IP/consent audit trail above are kept for 12 months by default,
            after which a scheduled job deletes them automatically. Terms/Acceptable-Use acceptance
            records are kept for as long as the associated account exists, since proof of what you
            agreed to needs to survive as long as the account does.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">4. Your rights</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] You can request deletion of your own account data
            (your consent/acceptance records — see the distinction in section 1) at any time. As of
            this version, that is available as an API action for signed-in accounts; a dedicated
            in-product control has not shipped yet — contact us in the meantime via the report form
            on{' '}
            <Link href="/about-this-scanner" className="underline underline-offset-2">
              /about-this-scanner
            </Link>
            .
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">5. Cookies</h2>
          <p className="mt-2">
            [PLACEHOLDER — REQUIRES LEGAL REVIEW] We use a small number of strictly necessary and
            functional cookies/local storage entries (e.g. remembering that you dismissed the cookie
            notice). We do not currently use third-party advertising or tracking cookies.
          </p>
        </section>

        <section>
          <h2 className="text-foreground font-medium">6. Changes to this policy</h2>
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
