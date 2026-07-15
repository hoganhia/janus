import Link from 'next/link';

export function Topbar() {
  return (
    <header className="border-border/60 flex items-center justify-between border-b px-6 py-4">
      <Link href="/" className="flex items-center gap-2 font-mono text-sm font-semibold">
        <span className="bg-primary shadow-primary/50 relative flex size-2 rounded-full shadow-[0_0_8px]">
          <span className="bg-primary absolute inline-flex size-full animate-ping rounded-full opacity-75" />
        </span>
        PERIMETER <span className="text-muted-foreground font-normal">{'// external scan'}</span>
      </Link>
      <nav className="font-mono text-sm">
        <Link href="/methodology" className="text-muted-foreground hover:text-foreground">
          Methodology
        </Link>
      </nav>
    </header>
  );
}
