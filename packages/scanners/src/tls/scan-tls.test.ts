import type { ScanFinding } from '@janus/shared';
import type { PeerCertificate, TLSSocket } from 'node:tls';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { connectTlsSocket } from './connect.js';
import { scanTLS } from './scan-tls.js';
import type { TlsProtocolVersion } from './connect.js';
import { probeSupportedTlsVersions } from './version-probe.js';

vi.mock('./connect.js', () => ({ connectTlsSocket: vi.fn() }));
vi.mock('./version-probe.js', () => ({ probeSupportedTlsVersions: vi.fn() }));

const mockConnect = vi.mocked(connectTlsSocket);
const mockProbeVersions = vi.mocked(probeSupportedTlsVersions);

const DAY_MS = 24 * 60 * 60 * 1000;

const MODERN_ONLY = new Map<TlsProtocolVersion, boolean>([
  ['TLSv1', false],
  ['TLSv1.1', false],
  ['TLSv1.2', true],
  ['TLSv1.3', true],
]);

interface FakeCertOverrides {
  subject?: Partial<PeerCertificate['subject']>;
  issuer?: Partial<PeerCertificate['issuer']>;
  valid_from?: string;
  valid_to?: string;
}

function fakeCert(overrides: FakeCertOverrides = {}): PeerCertificate {
  return {
    subject: { CN: 'example.com', ...overrides.subject },
    issuer: { CN: 'Example CA', O: 'Example CA Org', ...overrides.issuer },
    valid_from: overrides.valid_from ?? new Date(Date.now() - DAY_MS).toUTCString(),
    valid_to: overrides.valid_to ?? new Date(Date.now() + 300 * DAY_MS).toUTCString(),
  } as unknown as PeerCertificate;
}

interface FakeSocketOptions {
  cert?: PeerCertificate;
  authorized?: boolean;
  authorizationErrorCode?: string;
  cipher?: { name: string; standardName: string; version: string };
}

function fakeSocket(options: FakeSocketOptions = {}): TLSSocket {
  const authorized = options.authorized ?? true;
  return {
    on: vi.fn(),
    destroy: vi.fn(),
    getPeerCertificate: () => options.cert ?? fakeCert(),
    authorized,
    // Matches what a real socket actually returns: a plain string, not an Error/{code} object
    // — verified directly against a live Node tls handshake (@types/node's `Error` type is wrong).
    authorizationError: authorized
      ? undefined
      : (options.authorizationErrorCode ?? 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'),
    getCipher: () =>
      options.cipher ?? {
        name: 'TLS_AES_128_GCM_SHA256',
        standardName: 'TLS_AES_128_GCM_SHA256',
        version: 'TLSv1.3',
      },
  } as unknown as TLSSocket;
}

function findingsById(findings: ScanFinding[]): Map<string, ScanFinding> {
  return new Map(findings.map((f) => [f.id, f]));
}

describe('scanTLS', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('never throws when the connection itself fails', async () => {
    mockConnect.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const result = await scanTLS('example.com', '93.184.216.34');
    expect(result.findings).toEqual([
      expect.objectContaining({ id: 'tls.connection', status: 'fail' }),
    ]);
  });

  it('reports a missing certificate without crashing, alongside the connection-level checks', async () => {
    mockConnect.mockResolvedValueOnce(fakeSocket({ cert: {} as PeerCertificate }));
    mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
    const result = await scanTLS('example.com', '93.184.216.34');
    const findings = findingsById(result.findings);
    // No certificate-specific findings (validity/self-signed/issuer) beyond "presence" itself —
    // but cipher/protocol/HSTS are properties of the connection, not the cert, so they still run.
    expect(findings.get('tls.certificate.presence')?.status).toBe('fail');
    expect(findings.has('tls.certificate.validity')).toBe(false);
    expect(findings.has('tls.certificate.self-signed')).toBe(false);
    expect(findings.get('tls.cipher.strength')?.status).toBe('pass');
  });

  describe('certificate validity', () => {
    it('fails an expired certificate', async () => {
      mockConnect.mockResolvedValueOnce(
        fakeSocket({
          cert: fakeCert({
            valid_from: new Date(Date.now() - 400 * DAY_MS).toUTCString(),
            valid_to: new Date(Date.now() - DAY_MS).toUTCString(),
          }),
        }),
      );
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.certificate.validity')?.status).toBe('fail');
    });

    it('fails a not-yet-valid certificate', async () => {
      mockConnect.mockResolvedValueOnce(
        fakeSocket({
          cert: fakeCert({
            valid_from: new Date(Date.now() + DAY_MS).toUTCString(),
            valid_to: new Date(Date.now() + 400 * DAY_MS).toUTCString(),
          }),
        }),
      );
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.certificate.validity')?.status).toBe('fail');
    });

    it('warns when a certificate expires within 30 days', async () => {
      mockConnect.mockResolvedValueOnce(
        fakeSocket({
          cert: fakeCert({ valid_to: new Date(Date.now() + 10 * DAY_MS).toUTCString() }),
        }),
      );
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.certificate.validity')?.status).toBe('warning');
    });

    it('passes a certificate that is comfortably valid', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket());
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.certificate.validity')?.status).toBe('pass');
    });
  });

  describe('trust chain', () => {
    it('flags a self-signed certificate via the authorization error', async () => {
      mockConnect.mockResolvedValueOnce(
        fakeSocket({ authorized: false, authorizationErrorCode: 'DEPTH_ZERO_SELF_SIGNED_CERT' }),
      );
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      const findings = findingsById(result.findings);
      expect(findings.get('tls.certificate.self-signed')?.status).toBe('fail');
      // Issuer trust isn't a separate, meaningful finding once we already know it's self-signed.
      expect(findings.has('tls.certificate.issuer')).toBe(false);
    });

    it('flags a self-signed certificate via the issuer/subject heuristic when the error code is ambiguous and O is absent on both sides', async () => {
      // Built directly (not via fakeCert's default-merging) so neither issuer nor subject
      // carries an `O` field at all — the scenario this heuristic needs to handle. Not
      // authorized, but with a generic error code (not DEPTH_ZERO_SELF_SIGNED_CERT /
      // SELF_SIGNED_CERT_IN_CHAIN), so it's the CN/O heuristic — not the direct code match —
      // that has to catch this one. The heuristic is never consulted when `authorized` is
      // true (see isSelfSigned): trusting Node's own chain verification over a CN/O
      // coincidence avoids false-flagging two unrelated, legitimately-issued certificates
      // that happen to share a generic CN.
      const noOrgCert = {
        subject: { CN: 'example.com' },
        issuer: { CN: 'example.com' },
        valid_from: new Date(Date.now() - DAY_MS).toUTCString(),
        valid_to: new Date(Date.now() + 300 * DAY_MS).toUTCString(),
      } as unknown as PeerCertificate;
      mockConnect.mockResolvedValueOnce(
        fakeSocket({
          authorized: false,
          authorizationErrorCode: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
          cert: noOrgCert,
        }),
      );
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.certificate.self-signed')?.status).toBe('fail');
    });

    it('fails issuer trust when signed by an untrusted CA', async () => {
      mockConnect.mockResolvedValueOnce(
        fakeSocket({
          authorized: false,
          authorizationErrorCode: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        }),
      );
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      const findings = findingsById(result.findings);
      expect(findings.get('tls.certificate.self-signed')?.status).toBe('pass');
      expect(findings.get('tls.certificate.issuer')?.status).toBe('fail');
    });

    it('passes a certificate from a trusted CA', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket({ authorized: true }));
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      const findings = findingsById(result.findings);
      expect(findings.get('tls.certificate.self-signed')?.status).toBe('pass');
      expect(findings.get('tls.certificate.issuer')?.status).toBe('pass');
    });
  });

  describe('cipher strength', () => {
    it('fails a weak cipher', async () => {
      mockConnect.mockResolvedValueOnce(
        fakeSocket({
          cipher: {
            name: 'DES-CBC3-SHA',
            standardName: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
            version: 'TLSv1.2',
          },
        }),
      );
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.cipher.strength')?.status).toBe('fail');
    });

    it('passes a strong cipher', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket());
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.cipher.strength')?.status).toBe('pass');
    });
  });

  describe('protocol versions', () => {
    it('fails when TLS 1.0 or 1.1 are still enabled', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket());
      mockProbeVersions.mockResolvedValueOnce(
        new Map([
          ['TLSv1', true],
          ['TLSv1.1', false],
          ['TLSv1.2', true],
          ['TLSv1.3', true],
        ]),
      );
      const result = await scanTLS('example.com', '93.184.216.34');
      const finding = findingsById(result.findings).get('tls.protocol.outdated-versions');
      expect(finding?.status).toBe('fail');
      expect(finding?.explanation).toContain('TLS 1.0');
    });

    it('passes when only modern versions are supported', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket());
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.protocol.outdated-versions')?.status).toBe(
        'pass',
      );
      expect(findingsById(result.findings).get('tls.protocol.modern-versions')?.status).toBe(
        'pass',
      );
    });

    it('fails modern-version support when neither 1.2 nor 1.3 is available', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket());
      mockProbeVersions.mockResolvedValueOnce(
        new Map([
          ['TLSv1', true],
          ['TLSv1.1', true],
          ['TLSv1.2', false],
          ['TLSv1.3', false],
        ]),
      );
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.protocol.modern-versions')?.status).toBe(
        'fail',
      );
    });
  });

  describe('HSTS cross-check', () => {
    it('warns when no headers-scan result was provided', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket());
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34');
      expect(findingsById(result.findings).get('tls.hsts')?.status).toBe('warning');
    });

    it('passes when the headers scanner found the HSTS header', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket());
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34', { hstsHeaderPresent: true });
      expect(findingsById(result.findings).get('tls.hsts')?.status).toBe('pass');
    });

    it('warns (not fails) when the headers scanner found no HSTS header', async () => {
      mockConnect.mockResolvedValueOnce(fakeSocket());
      mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
      const result = await scanTLS('example.com', '93.184.216.34', { hstsHeaderPresent: false });
      expect(findingsById(result.findings).get('tls.hsts')?.status).toBe('warning');
    });
  });

  it('connects to the pinned address, not the hostname, with SNI set to the hostname', async () => {
    mockConnect.mockResolvedValueOnce(fakeSocket());
    mockProbeVersions.mockResolvedValueOnce(MODERN_ONLY);
    await scanTLS('example.com', '93.184.216.34', { port: 8443, timeoutMs: 1234 });
    expect(mockConnect).toHaveBeenCalledWith({
      pinnedAddress: '93.184.216.34',
      hostname: 'example.com',
      port: 8443,
      timeoutMs: 1234,
    });
  });
});
