import { ArrowLeft } from 'lucide-react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { Disclaimer } from '@/components/disclaimer';

export const metadata: Metadata = {
  title: 'Methodology — Perimeter',
};

const CATEGORIES = [
  {
    code: 'TLS',
    name: 'Transport Security',
    body: 'Checks the certificate and negotiated protocol/cipher on your public HTTPS endpoint — whether the certificate is valid and trusted, and whether the server still accepts outdated, weak TLS versions or ciphers.',
  },
  {
    code: 'HDR',
    name: 'HTTP Security Headers',
    body: 'Checks response headers like Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and cookie flags — the browser-enforced protections a site opts into by sending the right headers.',
  },
  {
    code: 'DNS',
    name: 'DNS & Email Security',
    body: 'Checks SPF, DMARC, and DNSSEC records — the DNS-level controls that make it harder for someone to spoof email from your domain or tamper with DNS responses in transit.',
  },
  {
    code: 'SFT',
    name: 'Software Hygiene',
    body: 'Checks publicly visible server/software identifiers (like a Server or X-Powered-By header) against known CVEs for that software, and flags anything that looks unpatched.',
  },
];

export default function MethodologyPage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <Link
        href="/"
        className="text-muted-foreground hover:text-foreground mb-10 inline-flex items-center gap-1.5 font-mono text-sm"
      >
        <ArrowLeft className="size-4" />
        Back to scan
      </Link>

      <h1 className="text-2xl font-semibold tracking-tight">Methodology</h1>
      <p className="text-muted-foreground mt-3 leading-relaxed">
        Perimeter runs a small set of passive, read-only checks against the public-facing side of a
        domain — the same information any visitor&apos;s browser or any DNS resolver can already
        see. Nothing here requires credentials, and nothing here writes to or modifies the target in
        any way.
      </p>

      <div className="mt-10 space-y-6">
        {CATEGORIES.map((category) => (
          <div key={category.code} className="border-border rounded-lg border p-5">
            <div className="flex items-center gap-2">
              <span className="border-border text-muted-foreground rounded border px-1.5 py-0.5 font-mono text-xs">
                {category.code}
              </span>
              <h2 className="font-medium">{category.name}</h2>
            </div>
            <p className="text-muted-foreground mt-2 text-sm leading-relaxed">{category.body}</p>
          </div>
        ))}
      </div>

      <h2 className="mt-10 font-medium">How grades are calculated</h2>
      <p className="text-muted-foreground mt-3 leading-relaxed">
        Each category gets its own letter grade based on the individual checks (findings) inside it.
        The overall grade is a weighted average across whichever categories were actually scanned —
        if a category couldn&apos;t be checked (for example, a scan target with no reachable HTTPS
        endpoint has no Transport Security category), it&apos;s excluded and the remaining
        categories are reweighted, not counted as a failure.
      </p>

      <div className="mt-10">
        <Disclaimer />
      </div>
    </main>
  );
}
