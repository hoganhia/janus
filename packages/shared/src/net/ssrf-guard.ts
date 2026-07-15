import { isIPv4, isIPv6 } from 'node:net';
import dns from 'node:dns/promises';

/** IANA special-purpose IPv4 ranges that must never be reachable from a passive scan. */
const BLOCKED_IPV4_CIDRS = [
  '0.0.0.0/8', // "this" network
  '10.0.0.0/8', // private
  '100.64.0.0/10', // carrier-grade NAT
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local (includes 169.254.169.254 cloud metadata)
  '172.16.0.0/12', // private
  '192.0.0.0/24', // IETF protocol assignments
  '192.0.2.0/24', // documentation (TEST-NET-1)
  '192.168.0.0/16', // private
  '198.18.0.0/15', // benchmarking
  '198.51.100.0/24', // documentation (TEST-NET-2)
  '203.0.113.0/24', // documentation (TEST-NET-3)
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved / broadcast
];

function ipv4ToInt(ip: string): number {
  const [a, b, c, d] = ip.split('.').map(Number);
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return (((a << 24) | (b << 16) | (c << 8) | d) >>> 0) >>> 0;
}

function isIpv4InCidr(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.split('/');
  if (base === undefined || bitsStr === undefined) {
    throw new Error(`Invalid CIDR: ${cidr}`);
  }
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

function isPrivateOrReservedIpv4(ip: string): boolean {
  return BLOCKED_IPV4_CIDRS.some((cidr) => isIpv4InCidr(ip, cidr));
}

type Ipv6Groups = [number, number, number, number, number, number, number, number];

/** Expands a valid IPv6 literal into its eight 16-bit groups, unpacking any embedded IPv4 tail. */
function expandIpv6(ip: string): Ipv6Groups {
  const parts = ip.split(':');
  const last = parts[parts.length - 1];

  if (last !== undefined && last.includes('.')) {
    const [a, b, c, d] = last.split('.').map(Number);
    if (a === undefined || b === undefined || c === undefined || d === undefined) {
      throw new Error(`Invalid IPv6 address: ${ip}`);
    }
    parts[parts.length - 1] = ((a << 8) | b).toString(16);
    parts.push((((c << 8) | d) >>> 0).toString(16));
  }

  const joined = parts.join(':');
  const doubleColonIndex = joined.indexOf('::');

  let hextets: string[];
  if (doubleColonIndex !== -1) {
    const head = joined.slice(0, doubleColonIndex);
    const tail = joined.slice(doubleColonIndex + 2);
    const headParts = head === '' ? [] : head.split(':');
    const tailParts = tail === '' ? [] : tail.split(':');
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) throw new Error(`Invalid IPv6 address: ${ip}`);
    hextets = [...headParts, ...(Array(missing).fill('0') as string[]), ...tailParts];
  } else {
    hextets = joined.split(':');
  }

  if (hextets.length !== 8) throw new Error(`Invalid IPv6 address: ${ip}`);
  return hextets.map((h) => parseInt(h === '' ? '0' : h, 16)) as Ipv6Groups;
}

function isPrivateOrReservedIpv6(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, '');
  const groups = expandIpv6(bare);
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;

  // ::ffff:0:0/96 (IPv4-mapped) and 64:ff9b::/96 (NAT64) embed an IPv4 address — check that instead.
  const isMapped = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff;
  const isNat64 = g0 === 0x0064 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0;
  if (isMapped || isNat64) {
    const embedded = [g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff].join('.');
    return isPrivateOrReservedIpv4(embedded);
  }

  const isUnspecifiedOrLoopback =
    [g0, g1, g2, g3, g4, g5, g6].every((g) => g === 0) && (g7 === 0 || g7 === 1);
  const isUniqueLocal = (g0 & 0xfe00) === 0xfc00; // fc00::/7
  const isLinkLocal = (g0 & 0xffc0) === 0xfe80; // fe80::/10
  const isMulticast = (g0 & 0xff00) === 0xff00; // ff00::/8
  const isDocumentation = g0 === 0x2001 && g1 === 0x0db8; // 2001:db8::/32

  return isUnspecifiedOrLoopback || isUniqueLocal || isLinkLocal || isMulticast || isDocumentation;
}

/** True if the given IP literal is private, loopback, link-local, or otherwise non-routable on the public internet. */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (isIPv4(ip)) return isPrivateOrReservedIpv4(ip);
  if (isIPv6(ip)) return isPrivateOrReservedIpv6(ip);
  return true; // not a recognizable IP literal — treat as unsafe rather than silently allow
}

export class UnsafeScanTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeScanTargetError';
  }
}

/**
 * Resolves a hostname and returns a single address to connect to, after confirming every
 * address the DNS answer returned is public. Scanners must connect to this pinned address
 * directly (not re-resolve the hostname) so a DNS answer that changes between validation and
 * connection — a rebinding attack — can't redirect the request into a private network.
 */
export async function resolvePublicAddress(
  hostname: string,
): Promise<{ address: string; family: 4 | 6 }> {
  const literal = hostname.replace(/^\[|\]$/g, '');
  if (isIPv4(literal) || isIPv6(literal)) {
    if (isPrivateOrReservedIp(literal)) {
      throw new UnsafeScanTargetError('Target resolves to a private or reserved address');
    }
    return { address: literal, family: isIPv4(literal) ? 4 : 6 };
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  const [first] = records;
  if (first === undefined) {
    throw new UnsafeScanTargetError('Target hostname did not resolve');
  }
  if (records.some((record) => isPrivateOrReservedIp(record.address))) {
    throw new UnsafeScanTargetError('Target resolves to a private or reserved address');
  }

  return { address: first.address, family: first.family as 4 | 6 };
}
