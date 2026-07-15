import Link from 'next/link';

export function Footer() {
  return (
    <footer className="border-border/60 text-muted-foreground mt-auto flex flex-wrap items-center justify-center gap-x-6 gap-y-2 border-t px-6 py-6 font-mono text-xs">
      <Link href="/terms" className="hover:text-foreground">
        Terms of Service
      </Link>
      <Link href="/acceptable-use" className="hover:text-foreground">
        Acceptable Use
      </Link>
      <Link href="/privacy" className="hover:text-foreground">
        Privacy
      </Link>
      <Link href="/methodology" className="hover:text-foreground">
        Methodology
      </Link>
      <Link href="/about-this-scanner" className="hover:text-foreground">
        About this scanner
      </Link>
    </footer>
  );
}
