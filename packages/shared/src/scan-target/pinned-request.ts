import net from 'node:net';
import tls from 'node:tls';
import { Agent, request as undiciRequest } from 'undici';

/**
 * Builds an undici dispatcher whose socket always connects to `pinnedAddress`, never to a
 * freshly-resolved address for `hostname` — this is what closes the DNS-rebinding window
 * between validating an address and connecting to it. The Host header and TLS SNI still use
 * the original hostname so virtual hosting and certificate validation behave normally.
 */
function buildPinnedDispatcher(
  pinnedAddress: string,
  hostname: string,
  port: number,
  isHttps: boolean,
): Agent {
  return new Agent({
    connect: (_options, callback) => {
      if (isHttps) {
        const socket = tls.connect({ host: pinnedAddress, port, servername: hostname });
        socket.once('secureConnect', () => {
          callback(null, socket);
        });
        socket.once('error', (err: Error) => {
          callback(err, null);
        });
      } else {
        const socket = net.connect({ host: pinnedAddress, port });
        socket.once('connect', () => {
          callback(null, socket);
        });
        socket.once('error', (err: Error) => {
          callback(err, null);
        });
      }
    },
  });
}

function resolvePort(url: URL, isHttps: boolean): number {
  return url.port ? Number(url.port) : isHttps ? 443 : 80;
}

function buildRequestHeaders(url: URL, userAgent: string | undefined): Record<string, string> {
  return { host: url.host, ...(userAgent !== undefined ? { 'user-agent': userAgent } : {}) };
}

export interface PinnedProbeResult {
  statusCode: number;
  location: string | undefined;
}

/**
 * Issues a single lightweight (HEAD) request against `url`, but connects the socket directly
 * to `pinnedAddress` instead of letting undici resolve the hostname itself.
 *
 * Redirects are never auto-followed: the caller inspects `location` and must re-validate the
 * target before following it.
 */
export async function probePinned(
  url: URL,
  pinnedAddress: string,
  options: { userAgent?: string } = {},
): Promise<PinnedProbeResult> {
  const isHttps = url.protocol === 'https:';
  const port = resolvePort(url, isHttps);
  const dispatcher = buildPinnedDispatcher(pinnedAddress, url.hostname, port, isHttps);

  try {
    const { statusCode, headers, body } = await undiciRequest(url, {
      method: 'HEAD',
      dispatcher,
      headers: buildRequestHeaders(url, options.userAgent),
      headersTimeout: 5000,
      bodyTimeout: 5000,
    });
    await body.dump();

    const locationHeader = headers.location;
    const location = Array.isArray(locationHeader) ? locationHeader[0] : locationHeader;
    return { statusCode, location };
  } finally {
    await dispatcher.close();
  }
}

export interface FetchPinnedOptions {
  userAgent?: string;
  headersTimeoutMs?: number;
  bodyTimeoutMs?: number;
  /** Response bodies are never fully buffered — reading stops (and the connection is torn
   * down) the moment this many bytes have been read, to protect the scanner itself from a
   * target sending an unbounded or malicious response. */
  maxBodyBytes: number;
  /** Off by default (the original scanHeaders use case never needs body content, only its
   * size). Scanners that do need to inspect body content — e.g. reading a version string out
   * of a known static file — can opt in; the byte-limit behavior above still applies either way. */
  captureBody?: boolean;
}

export interface PinnedFetchResult {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  bodyBytesRead: number;
  /** True if the response body was larger than `maxBodyBytes` and reading was cut short. */
  bodyTruncated: boolean;
  /** Only populated when `captureBody` is set; holds whatever was read before any truncation. */
  body?: Buffer;
}

/**
 * Issues a single GET request pinned to `pinnedAddress`, for scanners that need the full
 * response headers (and, unlike `probePinned`, can't just discard the body — some servers
 * don't finish sending headers, or behave inconsistently, until the body starts flowing).
 * The body's *content* is never returned or buffered in full: it's read only far enough to
 * enforce `maxBodyBytes`, then the connection is destroyed. This guards the scanner against
 * a target that responds with an enormous or infinite body.
 */
export async function fetchPinned(
  url: URL,
  pinnedAddress: string,
  options: FetchPinnedOptions,
): Promise<PinnedFetchResult> {
  const isHttps = url.protocol === 'https:';
  const port = resolvePort(url, isHttps);
  const dispatcher = buildPinnedDispatcher(pinnedAddress, url.hostname, port, isHttps);

  try {
    const { statusCode, headers, body } = await undiciRequest(url, {
      method: 'GET',
      dispatcher,
      headers: buildRequestHeaders(url, options.userAgent),
      headersTimeout: options.headersTimeoutMs ?? 5000,
      bodyTimeout: options.bodyTimeoutMs ?? 5000,
    });

    let bodyBytesRead = 0;
    let bodyTruncated = false;
    const chunks: Buffer[] = [];
    try {
      for await (const chunk of body) {
        bodyBytesRead += (chunk as Buffer).length;
        if (options.captureBody === true) chunks.push(chunk as Buffer);
        if (bodyBytesRead > options.maxBodyBytes) {
          bodyTruncated = true;
          body.destroy();
          break;
        }
      }
    } catch (err) {
      // Our own destroy() above can surface as a stream error on some undici versions —
      // only rethrow if the body wasn't already deliberately cut short.
      if (!bodyTruncated) throw err;
    }

    return {
      statusCode,
      headers,
      bodyBytesRead,
      bodyTruncated,
      ...(options.captureBody === true ? { body: Buffer.concat(chunks) } : {}),
    };
  } finally {
    await dispatcher.close();
  }
}
