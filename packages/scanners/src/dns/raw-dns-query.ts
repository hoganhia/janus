import dgram from 'node:dgram';
import dns from 'node:dns';
import net from 'node:net';
import dnsPacket, { type Answer, type DecodedPacket, type Packet } from 'dns-packet';

/**
 * Node's built-in `dns` module cannot query DS or DNSKEY records at all — `dns.promises.resolve()`
 * rejects synchronously with `ERR_INVALID_ARG_VALUE` for either rrtype, and `resolveAny()`
 * returns nothing useful (most resolvers now refuse ANY queries per RFC 8482). Both were
 * verified directly against live DNSSEC-signed domains before writing this module. This is a
 * minimal, purpose-built UDP/TCP DNS client — using `dns-packet` only for wire-format
 * encode/decode, not as a general-purpose DNS client — solely to cover that gap.
 */
export type RawDnsRecordType = 'DS' | 'DNSKEY';

/**
 * `@types/dns-packet`'s `DecodedPacket` doesn't declare `rcode`, but the library does return
 * it — confirmed directly against live NXDOMAIN and NOERROR responses. The community types are
 * incomplete here, not the runtime behavior.
 */
interface DecodedDnsPacket extends DecodedPacket {
  rcode?: string;
}

export type RawDnsErrorCode = 'NXDOMAIN' | 'SERVER_FAILURE' | 'TIMEOUT' | 'NETWORK_ERROR';

export class RawDnsQueryError extends Error {
  readonly code: RawDnsErrorCode;
  constructor(message: string, code: RawDnsErrorCode) {
    super(message);
    this.name = 'RawDnsQueryError';
    this.code = code;
  }
}

export interface RawDnsQueryOptions {
  /** Defaults to the first OS-configured resolver, falling back to a public resolver (1.1.1.1). */
  server?: string;
  port?: number;
  timeoutMs?: number;
}

const DEFAULT_PORT = 53;
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_FALLBACK_SERVER = '1.1.1.1';

function defaultServer(): string {
  return dns.getServers()[0] ?? DEFAULT_FALLBACK_SERVER;
}

function buildQueryPacket(name: string, type: RawDnsRecordType, id: number): Packet {
  return {
    type: 'query',
    id,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name, class: 'IN' }],
    // Requests a larger UDP payload via EDNS0 so typical DNSKEY/DS answers fit without
    // truncation; queryTcp is still there as a fallback for the rare response that doesn't.
    // @types/dns-packet's OptAnswer requires fields (extendedRcode, flags, ...) that the
    // library actually fills in with defaults at runtime — verified against live queries.
    additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 4096 } as unknown as Answer],
  };
}

function randomQueryId(): number {
  return Math.floor(Math.random() * 65534) + 1;
}

function queryUdp(
  name: string,
  type: RawDnsRecordType,
  id: number,
  server: string,
  port: number,
  timeoutMs: number,
): Promise<DecodedDnsPacket> {
  return new Promise((resolve, reject) => {
    const query = dnsPacket.encode(buildQueryPacket(name, type, id));
    const socket = dgram.createSocket('udp4');
    let settled = false;

    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      fn();
    };

    const timer = setTimeout(() => {
      settle(() => {
        reject(new RawDnsQueryError(`DNS query for ${type} ${name} timed out`, 'TIMEOUT'));
      });
    }, timeoutMs);

    socket.once('error', (err: Error) => {
      settle(() => {
        reject(
          new RawDnsQueryError(
            `DNS query for ${type} ${name} failed: ${err.message}`,
            'NETWORK_ERROR',
          ),
        );
      });
    });

    socket.on('message', (msg) => {
      if (settled) return;
      let response: DecodedDnsPacket;
      try {
        response = dnsPacket.decode(msg);
      } catch {
        return; // Malformed or unrelated packet — keep waiting for the real response or timeout.
      }
      if (response.id !== id) return; // Not our query — ignore (a stray or spoofed packet).
      settle(() => {
        resolve(response);
      });
    });

    socket.send(query, port, server, (err) => {
      if (err) {
        settle(() => {
          reject(new RawDnsQueryError(`Failed to send DNS query: ${err.message}`, 'NETWORK_ERROR'));
        });
      }
    });
  });
}

function queryTcp(
  name: string,
  type: RawDnsRecordType,
  id: number,
  server: string,
  port: number,
  timeoutMs: number,
): Promise<DecodedDnsPacket> {
  return new Promise((resolve, reject) => {
    const query = dnsPacket.streamEncode(buildQueryPacket(name, type, id));
    const socket = net.connect({ host: server, port });
    let settled = false;
    let buffered = Buffer.alloc(0);

    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      fn();
    };

    const timer = setTimeout(() => {
      settle(() => {
        reject(new RawDnsQueryError(`DNS/TCP query for ${type} ${name} timed out`, 'TIMEOUT'));
      });
    }, timeoutMs);

    socket.once('error', (err: Error) => {
      settle(() => {
        reject(
          new RawDnsQueryError(
            `DNS/TCP query for ${type} ${name} failed: ${err.message}`,
            'NETWORK_ERROR',
          ),
        );
      });
    });

    socket.once('connect', () => {
      socket.write(query);
    });

    socket.on('data', (chunk: Buffer) => {
      if (settled) return;
      buffered = Buffer.concat([buffered, chunk]);
      // The first two bytes are the message length prefix; wait until the full message has
      // arrived before attempting to decode.
      if (buffered.length < 2) return;
      const expectedLength = buffered.readUInt16BE(0) + 2;
      if (buffered.length < expectedLength) return;

      let response: DecodedDnsPacket;
      try {
        response = dnsPacket.streamDecode(buffered) as DecodedDnsPacket;
      } catch (err) {
        settle(() => {
          reject(
            new RawDnsQueryError(
              `Failed to decode DNS/TCP response: ${err instanceof Error ? err.message : String(err)}`,
              'NETWORK_ERROR',
            ),
          );
        });
        return;
      }
      settle(() => {
        resolve(response);
      });
    });
  });
}

function toAnswers(response: DecodedDnsPacket, name: string, type: RawDnsRecordType): Answer[] {
  if (response.rcode === 'NXDOMAIN') {
    throw new RawDnsQueryError(`${name} does not exist (NXDOMAIN)`, 'NXDOMAIN');
  }
  if (response.rcode !== undefined && response.rcode !== 'NOERROR') {
    throw new RawDnsQueryError(
      `DNS server returned ${response.rcode} for ${type} ${name}`,
      'SERVER_FAILURE',
    );
  }
  return response.answers ?? [];
}

/**
 * Queries a DS or DNSKEY record directly over UDP (falling back to TCP if the UDP response is
 * truncated), bypassing Node's `dns` module entirely since it can't request these record
 * types. Returns an empty array — not an error — when the record legitimately doesn't exist
 * (NOERROR with no matching answers, meaning DNSSEC isn't configured); NXDOMAIN and network
 * failures are thrown as `RawDnsQueryError` with a typed `code` for the caller to classify.
 */
export async function queryRawDns(
  name: string,
  type: RawDnsRecordType,
  options: RawDnsQueryOptions = {},
): Promise<Answer[]> {
  const server = options.server ?? defaultServer();
  const port = options.port ?? DEFAULT_PORT;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const id = randomQueryId();

  const udpResponse = await queryUdp(name, type, id, server, port, timeoutMs);
  if (!udpResponse.flag_tc) {
    return toAnswers(udpResponse, name, type);
  }

  const tcpResponse = await queryTcp(name, type, id, server, port, timeoutMs);
  return toAnswers(tcpResponse, name, type);
}
