import { connectTlsSocket, type TlsProtocolVersion } from './connect.js';

export const TLS_PROTOCOL_VERSIONS: readonly TlsProtocolVersion[] = [
  'TLSv1',
  'TLSv1.1',
  'TLSv1.2',
  'TLSv1.3',
];

/**
 * Determines whether the server accepts a specific TLS protocol version by forcing
 * `minVersion`/`maxVersion` to exactly that version and observing whether the handshake
 * completes. A failed handshake — including one caused by this Node runtime's own OpenSSL
 * build not offering an old protocol as a client option — is reported as "not supported";
 * there's no way to distinguish "server refused" from "our client couldn't offer it" without
 * a second, independently-built TLS client, so that ambiguity is an inherent limit of a
 * pure-Node-`tls` approach.
 */
export async function isTlsVersionSupported(
  pinnedAddress: string,
  hostname: string,
  port: number,
  version: TlsProtocolVersion,
  timeoutMs: number,
): Promise<boolean> {
  try {
    const socket = await connectTlsSocket({
      pinnedAddress,
      hostname,
      port,
      timeoutMs,
      minVersion: version,
      maxVersion: version,
    });
    socket.on('error', () => {
      // The connection is discarded immediately below; a late socket error must not crash
      // the process by going unhandled.
    });
    socket.destroy();
    return true;
  } catch {
    return false;
  }
}

export async function probeSupportedTlsVersions(
  pinnedAddress: string,
  hostname: string,
  port: number,
  timeoutMs: number,
): Promise<Map<TlsProtocolVersion, boolean>> {
  const results = await Promise.all(
    TLS_PROTOCOL_VERSIONS.map(
      async (version) =>
        [
          version,
          await isTlsVersionSupported(pinnedAddress, hostname, port, version, timeoutMs),
        ] as const,
    ),
  );
  return new Map(results);
}
