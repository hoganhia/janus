import { ArrowLeft } from 'lucide-react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { AbuseReportForm } from '@/components/abuse-report-form';

export const metadata: Metadata = {
  title: 'About this scanner — Janus',
};

const WHAT_WE_CHECK = [
  'The TLS certificate and negotiated protocol/cipher on your public HTTPS endpoint.',
  'HTTP response headers like Content-Security-Policy, Strict-Transport-Security, and cookie flags.',
  'DNS records: SPF, DMARC, and DNSSEC.',
  'A small, fixed list of publicly-visible software/version identifiers (e.g. a Server header) cross-referenced against known CVEs.',
];

const WHAT_WE_DONT_DO = [
  'No exploitation attempts, no injection payloads, no fuzzing — every check reads publicly-served responses, it never tries to trigger a vulnerability.',
  'No login attempts, credential stuffing, or any request requiring authentication.',
  'No load or denial-of-service style testing — request volume per target is small and bounded (see below).',
  'No scanning of pages or paths that require you to be signed in.',
  "No storing of anything beyond the scan target's domain and the check results themselves — no personal data is collected.",
];

export default function AboutThisScannerPage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <Link
        href="/"
        className="text-muted-foreground hover:text-foreground mb-10 inline-flex items-center gap-1.5 font-mono text-sm"
      >
        <ArrowLeft className="size-4" />
        Back to scan
      </Link>

      <h1 className="text-2xl font-semibold tracking-tight">About this scanner</h1>
      <p className="text-muted-foreground mt-3 leading-relaxed">
        Janus is a passive external scanner. This page explains exactly what it does, what it
        deliberately does not do, how often it makes requests, and how to opt out or block it if
        you&apos;d rather it left your domain alone.
      </p>

      <h2 className="mt-10 font-medium">What we check</h2>
      <ul className="text-muted-foreground mt-3 list-disc space-y-2 pl-5 text-sm leading-relaxed">
        {WHAT_WE_CHECK.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>

      <h2 className="mt-10 font-medium">What we don&apos;t do</h2>
      <ul className="text-muted-foreground mt-3 list-disc space-y-2 pl-5 text-sm leading-relaxed">
        {WHAT_WE_DONT_DO.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>

      <h2 className="mt-10 font-medium">Request rate &amp; frequency</h2>
      <p className="text-muted-foreground mt-3 text-sm leading-relaxed">
        Anyone can submit at most 5 scans per hour per IP address. Across every user combined, this
        system runs at most 5 scans at once and starts at most 30 scans per minute. A single scan
        makes a small, bounded number of requests to your domain — one TLS handshake, one HTTP
        request for headers, a handful of requests to well-known paths for software fingerprinting,
        and a few DNS lookups — all completed within roughly 20 seconds, then nothing further until
        (and unless) someone requests another scan of the same domain.
      </p>

      <h2 className="mt-10 font-medium">How to opt out</h2>
      <p className="text-muted-foreground mt-3 text-sm leading-relaxed">
        Add the following DNS TXT record to your zone, and every future scan of your domain will be
        refused before we make any request to it:
      </p>
      <pre className="border-border bg-card mt-3 overflow-x-auto rounded-lg border p-3 font-mono text-xs">
        _janus-opt-out.yourdomain.com. TXT &quot;true&quot;
      </pre>
      <p className="text-muted-foreground mt-3 text-sm leading-relaxed">
        This is checked fresh on every scan attempt (including redirects, at each hop), so it takes
        effect as soon as the record propagates — no need to contact us. The only exception is a
        domain whose owner has proven ownership through our verification flow and specifically
        requested a deeper scan of their own domain.
      </p>

      <h2 className="mt-10 font-medium">How to block by User-Agent</h2>
      <p className="text-muted-foreground mt-3 text-sm leading-relaxed">
        Every request this scanner makes identifies itself with a distinct, self-describing{' '}
        <code className="bg-card rounded px-1 py-0.5 text-xs">User-Agent</code> header — by default
        something like{' '}
        <code className="bg-card rounded px-1 py-0.5 text-xs">
          JanusSecurityScanner/1.0 (+https://.../about-this-scanner)
        </code>{' '}
        — that always links back to a page like this one. You can block or rate-limit it in your
        WAF, a robots.txt-style user-agent rule, or a firewall rule matching that string, in
        addition to (or instead of) the DNS opt-out record above.
      </p>

      <h2 className="mt-10 font-medium">Report a problem</h2>
      <p className="text-muted-foreground mt-3 text-sm leading-relaxed">
        If this scanner has caused you an issue, or you have a concern that isn&apos;t just
        &quot;stop scanning me&quot; (the DNS record above handles that immediately), tell us here:
      </p>
      <div className="mt-4">
        <AbuseReportForm />
      </div>
    </main>
  );
}
