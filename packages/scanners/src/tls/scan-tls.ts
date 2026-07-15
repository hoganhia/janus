import type { ScanFinding } from '@janus/shared';
import type { CipherNameAndProtocol, PeerCertificate } from 'node:tls';
import { isWeakCipher } from './cipher-strength.js';
import { connectTlsSocket } from './connect.js';
import type { TlsScanResult } from './types.js';
import { probeSupportedTlsVersions } from './version-probe.js';

export interface ScanTlsOptions {
  port?: number;
  timeoutMs?: number;
  /** Result of the headers scanner's Strict-Transport-Security check, if one has run. */
  hstsHeaderPresent?: boolean;
}

const DEFAULT_PORT = 443;
const DEFAULT_TIMEOUT_MS = 5000;
const CERT_EXPIRY_WARNING_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

// Treats "absent on both sides" as a match too, since a self-signed cert commonly omits
// fields like `O` entirely rather than setting them to an empty string on both issuer and
// subject — requiring both to be *present and equal* would silently miss that common case.
function fieldsMatch(a: string | string[] | undefined, b: string | string[] | undefined): boolean {
  return String(a ?? '') === String(b ?? '');
}

// Node's type declarations claim `TLSSocket.authorizationError` is always an `Error`, but at
// runtime it's a plain string (e.g. "DEPTH_ZERO_SELF_SIGNED_CERT") — verified directly against
// a live handshake. Handling both shapes defensively means this doesn't silently break again if
// a future Node version changes it to match its own types.
function extractAuthorizationErrorCode(authorizationError: unknown): string | undefined {
  if (typeof authorizationError === 'string') return authorizationError;
  if (authorizationError instanceof Error) {
    return (authorizationError as NodeJS.ErrnoException).code ?? authorizationError.message;
  }
  return undefined;
}

// Only consulted when the socket itself doesn't already trust the chain. If Node's own
// verification says the certificate is trusted, we don't second-guess that via a CN/O
// coincidence heuristic — doing so risks a false "self-signed" report for two entirely
// different, legitimately-issued certificates that happen to share a generic CN (and no O).
function isSelfSigned(
  cert: PeerCertificate,
  authorized: boolean,
  authorizationErrorCode: string | undefined,
): boolean {
  if (authorized) return false;
  if (authorizationErrorCode === 'DEPTH_ZERO_SELF_SIGNED_CERT') return true;
  if (authorizationErrorCode === 'SELF_SIGNED_CERT_IN_CHAIN') return true;
  const hasIdentity = cert.subject.CN !== undefined || cert.subject.O !== undefined;
  return (
    hasIdentity &&
    fieldsMatch(cert.issuer.CN, cert.subject.CN) &&
    fieldsMatch(cert.issuer.O, cert.subject.O)
  );
}

function buildCertificateFindings(
  cert: PeerCertificate,
  authorized: boolean,
  authorizationErrorCode: string | undefined,
): ScanFinding[] {
  // Node's PeerCertificate type claims `subject` is always present, but at runtime the socket
  // returns `{}` when no certificate was presented at all.
  if (Object.keys(cert).length === 0) {
    return [
      {
        id: 'tls.certificate.presence',
        label: 'Certificate presented',
        status: 'fail',
        explanation: 'The server did not present a TLS certificate.',
      },
    ];
  }

  const findings: ScanFinding[] = [];
  const now = Date.now();
  const validFrom = new Date(cert.valid_from).getTime();
  const validTo = new Date(cert.valid_to).getTime();

  if (Number.isNaN(validFrom) || Number.isNaN(validTo)) {
    findings.push({
      id: 'tls.certificate.validity',
      label: 'Certificate validity dates',
      status: 'warning',
      explanation: 'The certificate validity dates could not be read.',
    });
  } else if (now < validFrom) {
    findings.push({
      id: 'tls.certificate.validity',
      label: 'Certificate validity dates',
      status: 'fail',
      explanation: `This certificate is not valid yet — it doesn't take effect until ${cert.valid_from}.`,
    });
  } else if (now > validTo) {
    findings.push({
      id: 'tls.certificate.validity',
      label: 'Certificate validity dates',
      status: 'fail',
      explanation: `This certificate expired on ${cert.valid_to}. Visitors will see security warnings in their browser.`,
    });
  } else if (validTo - now < CERT_EXPIRY_WARNING_WINDOW_MS) {
    const daysLeft = Math.ceil((validTo - now) / (24 * 60 * 60 * 1000));
    findings.push({
      id: 'tls.certificate.validity',
      label: 'Certificate validity dates',
      status: 'warning',
      explanation: `This certificate is valid but expires soon — in about ${String(daysLeft)} day(s), on ${cert.valid_to}.`,
    });
  } else {
    findings.push({
      id: 'tls.certificate.validity',
      label: 'Certificate validity dates',
      status: 'pass',
      explanation: `This certificate is valid and doesn't expire until ${cert.valid_to}.`,
    });
  }

  const selfSigned = isSelfSigned(cert, authorized, authorizationErrorCode);
  findings.push({
    id: 'tls.certificate.self-signed',
    label: 'Self-signed certificate',
    status: selfSigned ? 'fail' : 'pass',
    explanation: selfSigned
      ? 'This certificate is self-signed rather than issued by a recognized certificate authority, so most browsers will show visitors a security warning.'
      : 'This certificate was issued by a certificate authority rather than self-signed.',
  });

  if (!selfSigned) {
    const issuerName = (cert.issuer.O ?? cert.issuer.CN ?? 'an unknown issuer').toString();
    findings.push({
      id: 'tls.certificate.issuer',
      label: 'Certificate issuer trust',
      status: authorizationErrorCode ? 'fail' : 'pass',
      explanation: authorizationErrorCode
        ? `This certificate was issued by ${issuerName}, but it failed trust validation (${authorizationErrorCode}).`
        : `This certificate was issued by a trusted certificate authority: ${issuerName}.`,
      details: { issuer: issuerName },
    });
  }

  return findings;
}

function buildCipherFinding(cipher: CipherNameAndProtocol): ScanFinding {
  const weak = isWeakCipher(cipher.name) || isWeakCipher(cipher.standardName);
  return {
    id: 'tls.cipher.strength',
    label: 'Cipher suite strength',
    status: weak ? 'fail' : 'pass',
    explanation: weak
      ? `The connection negotiated a weak cipher suite (${cipher.name}), which is considered insecure by modern standards.`
      : `The connection negotiated a strong cipher suite (${cipher.name}).`,
    details: { cipher: cipher.name, protocol: cipher.version },
  };
}

async function buildTlsVersionFindings(
  pinnedAddress: string,
  hostname: string,
  port: number,
  timeoutMs: number,
): Promise<ScanFinding[]> {
  const supported = await probeSupportedTlsVersions(pinnedAddress, hostname, port, timeoutMs);

  const enabledOutdated = [
    supported.get('TLSv1') === true ? 'TLS 1.0' : null,
    supported.get('TLSv1.1') === true ? 'TLS 1.1' : null,
  ].filter((v): v is string => v !== null);

  const outdatedFinding: ScanFinding = {
    id: 'tls.protocol.outdated-versions',
    label: 'Outdated TLS versions',
    status: enabledOutdated.length > 0 ? 'fail' : 'pass',
    explanation:
      enabledOutdated.length > 0
        ? `This server still accepts outdated, insecure protocol versions: ${enabledOutdated.join(', ')}. These have known weaknesses and should be disabled.`
        : 'This server did not accept connections using outdated TLS 1.0 or 1.1 during this scan.',
    details: {
      note: 'A scan environment that cannot itself offer TLS 1.0/1.1 as a client would also show as "not accepted" here, indistinguishable from the server genuinely rejecting them — this check is not a substitute for a dedicated legacy-protocol audit.',
      tlsV1: supported.get('TLSv1') ?? false,
      tlsV1_1: supported.get('TLSv1.1') ?? false,
    },
  };

  const supportsModern = supported.get('TLSv1.2') === true || supported.get('TLSv1.3') === true;
  const modernFinding: ScanFinding = {
    id: 'tls.protocol.modern-versions',
    label: 'Modern TLS support',
    status: supportsModern ? 'pass' : 'fail',
    explanation: supportsModern
      ? `This server supports a modern, secure TLS version (${supported.get('TLSv1.3') === true ? 'TLS 1.3' : 'TLS 1.2'}).`
      : 'This server does not appear to support TLS 1.2 or 1.3, which are required for a secure connection today.',
  };

  return [outdatedFinding, modernFinding];
}

function buildHstsFinding(hstsHeaderPresent: boolean | undefined): ScanFinding {
  if (hstsHeaderPresent === undefined) {
    return {
      id: 'tls.hsts',
      label: 'HTTP Strict Transport Security (HSTS)',
      status: 'warning',
      explanation: 'HSTS could not be checked because no HTTP header scan result was provided.',
    };
  }
  return {
    id: 'tls.hsts',
    label: 'HTTP Strict Transport Security (HSTS)',
    status: hstsHeaderPresent ? 'pass' : 'warning',
    explanation: hstsHeaderPresent
      ? 'This site sends the Strict-Transport-Security header, telling browsers to always use HTTPS for it.'
      : 'This site does not send a Strict-Transport-Security header, so browsers may still allow insecure HTTP connections to it.',
  };
}

function connectionFailureResult(
  hostname: string,
  port: number,
  scannedAt: string,
  err: unknown,
): TlsScanResult {
  return {
    hostname,
    port,
    scannedAt,
    findings: [
      {
        id: 'tls.connection',
        label: 'TLS connection',
        status: 'fail',
        explanation: `Could not establish a secure connection to ${hostname}:${String(port)}. The site may be down, blocking scans, or not serving HTTPS on this port.`,
        details: { error: err instanceof Error ? err.message : String(err) },
      },
    ],
  };
}

/**
 * Scans a target's TLS configuration: certificate validity/trust, protocol version support,
 * and negotiated cipher strength. `pinnedAddress` must come from `validateScanTarget` (or
 * another SSRF-validated resolution) — this function connects directly to that address and
 * never re-resolves `hostname` itself, by design. A scan failure is always returned as a
 * `fail` finding, never thrown, so a single unreachable target can't crash the worker.
 */
export async function scanTLS(
  hostname: string,
  pinnedAddress: string,
  options: ScanTlsOptions = {},
): Promise<TlsScanResult> {
  const port = options.port ?? DEFAULT_PORT;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const scannedAt = new Date().toISOString();

  try {
    // Start the version probe concurrently with the main connection — it doesn't depend on
    // anything the main connection produces, so running them one after another would roughly
    // double worst-case scan latency for no benefit. Crucially, though, we must not `await`
    // anything else between the main connection resolving and reading data off that socket:
    // some servers close the connection immediately after the handshake, and
    // `getPeerCertificate()`/`getCipher()` return null/stale data once the socket is
    // destroyed — so the main socket's data has to be read the instant it connects, not after
    // whatever else happens to be in flight.
    const versionFindingsPromise = buildTlsVersionFindings(
      pinnedAddress,
      hostname,
      port,
      timeoutMs,
    );
    // If the main connection below fails, this function returns before ever awaiting
    // versionFindingsPromise. Without a handler attached now, a later rejection of that
    // (currently-unused) promise would surface as an unhandled rejection — which can crash
    // the whole process — defeating the "a scan failure must never crash the worker"
    // guarantee this function exists to provide. The `void` catch below only suppresses that;
    // the real result (or a thrown rejection) is still awaited normally further down.
    versionFindingsPromise.catch(() => {});

    const socket = await connectTlsSocket({ pinnedAddress, hostname, port, timeoutMs });
    socket.on('error', () => {
      // The socket is destroyed immediately below; a late error must not go unhandled.
    });

    const cert = socket.getPeerCertificate(true);
    const authorized = socket.authorized;
    // `authorizationError` is only meaningful when `authorized` is false.
    const authorizationErrorCode = authorized
      ? undefined
      : extractAuthorizationErrorCode(socket.authorizationError);
    const cipher = socket.getCipher();
    socket.destroy();

    const versionFindings = await versionFindingsPromise;

    const findings: ScanFinding[] = [
      ...buildCertificateFindings(cert, authorized, authorizationErrorCode),
      buildCipherFinding(cipher),
      ...versionFindings,
      buildHstsFinding(options.hstsHeaderPresent),
    ];

    return { hostname, port, scannedAt, findings };
  } catch (err) {
    return connectionFailureResult(hostname, port, scannedAt, err);
  }
}
