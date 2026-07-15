import http from 'node:http';
import { fetchPinned } from '@janus/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { evaluateCookies } from './cookie-flags.js';
import { evaluateSecurityHeaders } from './security-headers.js';

/**
 * scanHeaders self-validates through validateScanTarget, which correctly refuses loopback
 * targets — so it can't be driven end-to-end against a local test server the way scanTLS's
 * integration test drives scanTLS. Instead, this exercises the real network + header-parsing
 * layer directly: fetchPinned doesn't self-validate (its caller, validateScanTarget, is
 * responsible for that), so it can be pointed at a local server here, and the real response it
 * returns is fed into the same evaluator functions scanHeaders itself calls.
 */
describe('header evaluators against a real HTTP response', () => {
  let server: http.Server;
  let port: number;

  beforeAll(async () => {
    server = http.createServer((_req, res) => {
      res.setHeader('set-cookie', [
        'session=abc123; Secure; HttpOnly; SameSite=Strict',
        'tracker=xyz; SameSite=None',
      ]);
      res.writeHead(200, {
        'content-security-policy': "default-src 'self'; script-src 'self'",
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'geolocation=()',
      });
      res.end('ok');
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

  it('reads real headers via fetchPinned and scores them correctly', async () => {
    const url = new URL(`http://localhost:${String(port)}/`);
    const response = await fetchPinned(url, '127.0.0.1', { maxBodyBytes: 1024 });

    expect(response.statusCode).toBe(200);
    expect(response.bodyTruncated).toBe(false);

    const findings = evaluateSecurityHeaders({
      csp: response.headers['content-security-policy'] as string,
      hsts: response.headers['strict-transport-security'] as string,
      xFrameOptions: response.headers['x-frame-options'] as string,
      xContentTypeOptions: response.headers['x-content-type-options'] as string,
      referrerPolicy: response.headers['referrer-policy'] as string,
      permissionsPolicy: response.headers['permissions-policy'] as string,
    });

    for (const finding of findings) {
      expect(finding.status, `${finding.id}: ${finding.explanation}`).toBe('pass');
    }

    const cookieFindings = evaluateCookies(response.headers['set-cookie'], true);
    const byId = new Map(cookieFindings.map((f) => [f.id, f]));
    expect(byId.get('cookie.session')?.status).toBe('pass');
    // SameSite=None without Secure — a real, invalid combination the browser will reject.
    expect(byId.get('cookie.tracker')?.status).toBe('fail');
  });

  it('actually enforces the byte limit against a real oversized body', async () => {
    const bigServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(Buffer.alloc(5 * 1024 * 1024, 'x'));
    });
    await new Promise<void>((resolve) => bigServer.listen(0, '127.0.0.1', resolve));
    const address = bigServer.address();
    if (address === null || typeof address === 'string') {
      throw new Error('expected server to bind to a TCP port');
    }

    const url = new URL(`http://localhost:${String(address.port)}/`);
    const start = Date.now();
    const response = await fetchPinned(url, '127.0.0.1', { maxBodyBytes: 64 * 1024 });
    const elapsedMs = Date.now() - start;

    expect(response.bodyTruncated).toBe(true);
    expect(response.bodyBytesRead).toBeLessThan(5 * 1024 * 1024);
    expect(elapsedMs).toBeLessThan(2000);

    bigServer.close();
  });
});
