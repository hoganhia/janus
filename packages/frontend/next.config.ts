import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Every scan result string (header values, TLS cert fields, DNS record content) comes from a
  // target the caller chose, not from us — see lib/api.ts and the components under app/reports.
  // Nothing here ever needs to render trusted HTML from that data, so there is deliberately no
  // dangerouslyAllowSVG/rewrites/etc. configuration that would widen that surface.
};

export default nextConfig;
