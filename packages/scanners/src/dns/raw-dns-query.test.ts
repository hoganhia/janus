import dgram from 'node:dgram';
import net from 'node:net';
import dnsPacket from 'dns-packet';
import { afterAll, describe, expect, it } from 'vitest';
import { queryRawDns, RawDnsQueryError } from './raw-dns-query.js';

/**
 * These tests hit real public DNS infrastructure (there is no local equivalent for "does a
 * real DNSSEC-signed zone answer a DS query correctly") — the same tradeoff made throughout
 * this scanner's development: verified directly against live servers rather than assumed.
 * The one thing that *can't* be relied on from real-world domains is triggering UDP
 * truncation on demand, so that path gets a local mock server instead (further down).
 */
describe('queryRawDns (real DNS)', () => {
  it('finds DS and DNSKEY records for a DNSSEC-signed domain', async () => {
    const [ds, dnskey] = await Promise.all([
      queryRawDns('cloudflare.com', 'DS'),
      queryRawDns('cloudflare.com', 'DNSKEY'),
    ]);
    expect(ds.length).toBeGreaterThan(0);
    expect(dnskey.length).toBeGreaterThan(0);
  });

  it('returns an empty array (not an error) for a domain without DNSSEC', async () => {
    const ds = await queryRawDns('google.com', 'DS');
    expect(ds).toEqual([]);
  });

  it('throws a typed NXDOMAIN error for a nonexistent domain', async () => {
    await expect(
      queryRawDns('this-domain-should-not-exist-abcxyz123.com', 'DS'),
    ).rejects.toMatchObject({
      code: 'NXDOMAIN',
    });
    await expect(
      queryRawDns('this-domain-should-not-exist-abcxyz123.com', 'DS'),
    ).rejects.toBeInstanceOf(RawDnsQueryError);
  });

  it('times out against a non-responding server rather than hanging', async () => {
    // 192.0.2.1 is TEST-NET-1 (RFC 5737) — reserved for documentation, guaranteed unroutable.
    await expect(
      queryRawDns('example.com', 'DS', { server: '192.0.2.1', timeoutMs: 500 }),
    ).rejects.toMatchObject({ code: 'TIMEOUT' });
  }, 10000);
});

describe('queryRawDns TCP fallback (local mock server)', () => {
  const REAL_ANSWER = {
    name: 'example.com',
    type: 'DS' as const,
    class: 'IN' as const,
    ttl: 3600,
    data: { keyTag: 1234, algorithm: 13, digestType: 2, digest: Buffer.alloc(32, 1) },
  };

  let udpServer: dgram.Socket;
  let tcpServer: net.Server;
  let port: number;

  afterAll(() => {
    udpServer.close();
    tcpServer.close();
  });

  it('falls back to TCP when the UDP response is truncated, and returns the TCP answer', async () => {
    tcpServer = net.createServer((socket) => {
      let buffered = Buffer.alloc(0);
      socket.on('data', (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk]);
        if (buffered.length < 2) return;
        const expected = buffered.readUInt16BE(0) + 2;
        if (buffered.length < expected) return;
        const query = dnsPacket.streamDecode(buffered);
        const response = dnsPacket.streamEncode({
          type: 'response',
          id: query.id,
          flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE,
          questions: query.questions,
          answers: [REAL_ANSWER],
        });
        socket.end(response);
      });
    });
    await new Promise<void>((resolve) => tcpServer.listen(0, '127.0.0.1', resolve));
    const tcpAddress = tcpServer.address();
    if (tcpAddress === null || typeof tcpAddress === 'string') throw new Error('expected TCP port');
    port = tcpAddress.port;

    udpServer = dgram.createSocket('udp4');
    udpServer.on('message', (msg, rinfo) => {
      const query = dnsPacket.decode(msg);
      // Always respond truncated with no answers, forcing the client to retry over TCP.
      const response = dnsPacket.encode({
        type: 'response',
        id: query.id,
        flags: dnsPacket.RECURSION_DESIRED | dnsPacket.TRUNCATED_RESPONSE,
        questions: query.questions,
        answers: [],
      });
      udpServer.send(response, rinfo.port, rinfo.address);
    });
    await new Promise<void>((resolve) => udpServer.bind(port, '127.0.0.1', resolve));

    const answers = await queryRawDns('example.com', 'DS', {
      server: '127.0.0.1',
      port,
      timeoutMs: 3000,
    });
    expect(answers).toHaveLength(1);
    expect(answers[0]?.name).toBe('example.com');
  });
});
