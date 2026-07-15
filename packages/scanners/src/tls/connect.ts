import tls, { type TLSSocket } from 'node:tls';

export type TlsProtocolVersion = 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3';

export interface TlsConnectOptions {
  /** The SSRF-validated IP address to actually open the socket to — never a hostname. */
  pinnedAddress: string;
  /** Original hostname, used only for SNI/certificate-name matching. */
  hostname: string;
  port: number;
  timeoutMs: number;
  minVersion?: TlsProtocolVersion;
  maxVersion?: TlsProtocolVersion;
}

/**
 * Opens a TLS connection pinned to a validated IP address (SNI still uses the original
 * hostname), enforcing `timeoutMs` via `socket.setTimeout`. Certificate errors are not
 * treated as connection failures — `rejectUnauthorized` is off so scanners can inspect and
 * report on invalid/self-signed/expired certificates rather than simply failing to connect.
 */
export function connectTlsSocket(options: TlsConnectOptions): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    let settled = false;

    let socket: TLSSocket;
    try {
      socket = tls.connect({
        host: options.pinnedAddress,
        port: options.port,
        servername: options.hostname,
        rejectUnauthorized: false,
        minVersion: options.minVersion,
        maxVersion: options.maxVersion,
      });
    } catch (err) {
      reject(err instanceof Error ? err : new Error(String(err)));
      return;
    }

    socket.setTimeout(options.timeoutMs, () => {
      if (settled) return;
      settled = true;
      socket.destroy(new Error('TLS connection timed out'));
      reject(new Error('TLS connection timed out'));
    });

    socket.once('secureConnect', () => {
      if (settled) return;
      settled = true;
      socket.setTimeout(0);
      resolve(socket);
    });

    socket.once('error', (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}
