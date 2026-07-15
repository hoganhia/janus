import dns from 'node:dns/promises';
import { afterEach, describe, expect, it, vi, type Mock } from 'vitest';
import {
  isPrivateOrReservedIp,
  resolvePublicAddress,
  UnsafeScanTargetError,
} from './ssrf-guard.js';

vi.mock('node:dns/promises', () => {
  const lookup = vi.fn();
  return { default: { lookup }, lookup };
});

// dns.lookup is heavily overloaded (single result vs. array, depending on the `all` option);
// the mock is only ever driven with the `{ all: true }` shape resolvePublicAddress actually uses.
const mockLookup = dns.lookup as unknown as Mock;

describe('isPrivateOrReservedIp', () => {
  it.each([
    ['169.254.169.254', true, 'cloud metadata address'],
    ['127.0.0.1', true, 'loopback'],
    ['10.1.2.3', true, 'RFC1918 10/8'],
    ['172.16.0.1', true, 'RFC1918 172.16/12 start'],
    ['172.31.255.255', true, 'RFC1918 172.16/12 end'],
    ['172.32.0.1', false, 'just outside 172.16/12'],
    ['192.168.1.1', true, 'RFC1918 192.168/16'],
    ['100.64.0.1', true, 'carrier-grade NAT'],
    ['0.0.0.0', true, 'unspecified'],
    ['224.0.0.1', true, 'multicast'],
    ['8.8.8.8', false, 'public (google dns)'],
    ['1.1.1.1', false, 'public (cloudflare dns)'],
    ['::1', true, 'IPv6 loopback'],
    ['::', true, 'IPv6 unspecified'],
    ['fe80::1', true, 'IPv6 link-local'],
    ['fc00::1', true, 'IPv6 unique local'],
    ['fd12:3456:789a::1', true, 'IPv6 unique local (fd)'],
    ['2001:db8::1', true, 'IPv6 documentation range'],
    ['::ffff:127.0.0.1', true, 'IPv4-mapped loopback'],
    ['::ffff:169.254.169.254', true, 'IPv4-mapped cloud metadata'],
    ['::ffff:8.8.8.8', false, 'IPv4-mapped public address'],
    ['2606:4700:4700::1111', false, 'public IPv6 (cloudflare dns)'],
  ])('treats %s as private=%s (%s)', (ip, expected) => {
    expect(isPrivateOrReservedIp(ip)).toBe(expected);
  });
});

describe('decimal/hex/octal IPv4 encoding bypass', () => {
  it.each([
    ['http://2130706433/', '127.0.0.1'],
    ['http://0x7f000001/', '127.0.0.1'],
    ['http://0177.0.0.1/', '127.0.0.1'],
    ['http://127.1/', '127.0.0.1'],
  ])('WHATWG URL normalizes %s to %s, which is then caught as private', (raw, expectedHostname) => {
    const url = new URL(raw);
    expect(url.hostname).toBe(expectedHostname);
    expect(isPrivateOrReservedIp(url.hostname)).toBe(true);
  });
});

describe('resolvePublicAddress', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('rejects an IP-literal target without performing a DNS lookup', async () => {
    await expect(resolvePublicAddress('169.254.169.254')).rejects.toThrow(UnsafeScanTargetError);
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('accepts a public IP-literal target without performing a DNS lookup', async () => {
    await expect(resolvePublicAddress('8.8.8.8')).resolves.toEqual({
      address: '8.8.8.8',
      family: 4,
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('rejects a hostname if any resolved address is private', async () => {
    mockLookup.mockResolvedValueOnce([
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.5', family: 4 },
    ]);
    await expect(resolvePublicAddress('multi-answer.example')).rejects.toThrow(
      UnsafeScanTargetError,
    );
  });

  it('resolves and pins the first address when every resolved address is public', async () => {
    mockLookup.mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }]);
    await expect(resolvePublicAddress('good.example')).resolves.toEqual({
      address: '93.184.216.34',
      family: 4,
    });
  });

  it('rejects a hostname that does not resolve', async () => {
    mockLookup.mockResolvedValueOnce([]);
    await expect(resolvePublicAddress('nowhere.example')).rejects.toThrow(UnsafeScanTargetError);
  });
});
