import Link from 'next/link';
import { ScanConsole } from '@/components/scan-console';

const SAMPLE_REPORT_ID = 'cmrmg3nom000201nxh6ku363o';

const TRUST_STATS = [
  { value: '04', label: 'check categories' },
  { value: '0', label: 'data stored without consent' },
  { value: '100%', label: 'passive, non-intrusive' },
];

export default function Home() {
  return (
    <main className="mx-auto flex max-w-3xl flex-col items-center px-6 py-20 text-center">
      <p className="text-primary font-mono text-xs tracking-widest uppercase">
        Passive · read-only · takes ~20 seconds
      </p>

      <h1 className="mt-6 text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
        See what the internet already sees about <span className="text-primary">your site.</span>
      </h1>

      <p className="text-muted-foreground mt-5 max-w-xl text-balance">
        Run a passive external scan of your domain&apos;s TLS configuration, security headers, DNS
        &amp; email protections, and software hygiene — no login, no agents installed, no changes
        made.
      </p>

      <div className="mt-10 w-full">
        <ScanConsole />
      </div>

      <Link
        href={`/reports/${SAMPLE_REPORT_ID}`}
        className="text-muted-foreground hover:text-foreground mt-4 text-sm underline underline-offset-4"
      >
        Or view a sample report →
      </Link>

      <dl className="text-muted-foreground mt-16 grid w-full max-w-xl grid-cols-3 gap-6 font-mono text-xs">
        {TRUST_STATS.map((stat) => (
          <div key={stat.label}>
            <dt className="text-foreground text-lg font-semibold">{stat.value}</dt>
            <dd className="mt-1">{stat.label}</dd>
          </div>
        ))}
      </dl>
    </main>
  );
}
