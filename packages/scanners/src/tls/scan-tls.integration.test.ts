import tls from 'node:tls';
import selfsigned from 'selfsigned';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanTLS } from './scan-tls.js';

/**
 * Exercises scanTLS against a *real* TLS handshake (self-signed cert, real socket, real
 * OpenSSL-negotiated cipher/protocol) rather than mocked objects — the classification logic
 * is covered separately in scan-tls.test.ts, but only a real handshake proves the actual
 * `node:tls` usage (pinned-address connect, version forcing, cert/cipher extraction) works.
 */
describe('scanTLS (real local TLS server)', () => {
  let server: tls.Server;
  let port: number;

  beforeAll(async () => {
    const pems = await selfsigned.generate([{ name: 'commonName', value: 'localhost' }]);
    server = tls.createServer({ key: pems.private, cert: pems.cert }, (socket) => {
      socket.end();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (address === null || typeof address === 'string') {
      throw new Error('expected server to bind to a TCP port');
    }
    port = address.port;
  });

  afterAll(() => {
    server.close();
  });

  it('detects the self-signed certificate and reports a strong, modern connection', async () => {
    const result = await scanTLS('localhost', '127.0.0.1', { port, timeoutMs: 3000 });

    const byId = new Map(result.findings.map((f) => [f.id, f]));

    expect(byId.get('tls.certificate.self-signed')?.status).toBe('fail');
    expect(byId.get('tls.certificate.validity')?.status).toBe('pass');
    expect(byId.get('tls.cipher.strength')?.status).toBe('pass');
    // Node's default secure context rejects TLS 1.0/1.1 handshakes, so a plain
    // tls.createServer() with no explicit minVersion should already look "hardened".
    expect(byId.get('tls.protocol.outdated-versions')?.status).toBe('pass');
    expect(byId.get('tls.protocol.modern-versions')?.status).toBe('pass');
    // No headers-scanner result was passed in.
    expect(byId.get('tls.hsts')?.status).toBe('warning');
  });

  it('cross-checks a provided HSTS header result', async () => {
    const result = await scanTLS('localhost', '127.0.0.1', {
      port,
      timeoutMs: 3000,
      hstsHeaderPresent: true,
    });
    const hsts = result.findings.find((f) => f.id === 'tls.hsts');
    expect(hsts?.status).toBe('pass');
  });

  it('never throws when the target port is closed — it returns a fail finding instead', async () => {
    const result = await scanTLS('localhost', '127.0.0.1', { port: 1, timeoutMs: 1000 });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.id).toBe('tls.connection');
    expect(result.findings[0]?.status).toBe('fail');
  });
});
