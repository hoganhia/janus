import { fetchPinned, validateScanTarget, type ValidatedScanTarget } from '@janus/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { scanHeaders } from './scan-headers.js';

vi.mock('@janus/shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/shared')>();
  return { ...actual, validateScanTarget: vi.fn(), fetchPinned: vi.fn() };
});

const mockValidate = vi.mocked(validateScanTarget);
const mockFetch = vi.mocked(fetchPinned);

const VALIDATED: ValidatedScanTarget = {
  requestedUrl: 'https://example.com/',
  finalUrl: 'https://example.com/',
  pinnedAddress: '93.184.216.34',
  family: 4,
  redirectCount: 0,
};

function baseHeaders() {
  return {
    'content-security-policy': "default-src 'self'",
    'strict-transport-security': 'max-age=31536000',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=()',
  };
}

describe('scanHeaders', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('validates the target, fetches once, and assembles findings from the response', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockResolvedValueOnce({
      statusCode: 200,
      headers: baseHeaders(),
      bodyBytesRead: 128,
      bodyTruncated: false,
    });

    const result = await scanHeaders('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'JanusTest/1.0 (+https://example.com/about)',
    });

    expect(result.url).toBe('https://example.com/');
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const byId = new Map(result.findings.map((f) => [f.id, f]));
    expect(byId.get('headers.csp')?.status).toBe('pass');
    expect(byId.get('cookies.none')?.status).toBe('pass');
  });

  it('passes maxRedirects through to validateScanTarget, defaulting to 3', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockResolvedValueOnce({
      statusCode: 200,
      headers: baseHeaders(),
      bodyBytesRead: 0,
      bodyTruncated: false,
    });

    await scanHeaders('https://example.com/', { requesterIp: '203.0.113.9', userAgent: 'UA/1.0' });

    expect(mockValidate).toHaveBeenCalledWith(
      'https://example.com/',
      expect.objectContaining({ maxRedirects: 3, userAgent: 'UA/1.0' }),
    );
  });

  it('honors a custom maxRedirects override', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockResolvedValueOnce({
      statusCode: 200,
      headers: baseHeaders(),
      bodyBytesRead: 0,
      bodyTruncated: false,
    });

    await scanHeaders('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
      maxRedirects: 1,
    });

    expect(mockValidate).toHaveBeenCalledWith(
      'https://example.com/',
      expect.objectContaining({ maxRedirects: 1 }),
    );
  });

  it('passes maxBodyBytes and timeouts through to fetchPinned, with defaults', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockResolvedValueOnce({
      statusCode: 200,
      headers: baseHeaders(),
      bodyBytesRead: 0,
      bodyTruncated: false,
    });

    await scanHeaders('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
      maxBodyBytes: 4096,
      headersTimeoutMs: 1000,
      bodyTimeoutMs: 2000,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(URL),
      '93.184.216.34',
      expect.objectContaining({
        maxBodyBytes: 4096,
        headersTimeoutMs: 1000,
        bodyTimeoutMs: 2000,
        userAgent: 'UA/1.0',
      }),
    );
  });

  it('never throws when validation rejects the target', async () => {
    const { ScanTargetRejectedError } =
      await vi.importActual<typeof import('@janus/shared')>('@janus/shared');
    mockValidate.mockRejectedValueOnce(new ScanTargetRejectedError('PRIVATE_ADDRESS', 'nope'));

    const result = await scanHeaders('http://internal.example/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.id).toBe('headers.connection');
    expect(result.findings[0]?.status).toBe('fail');
    expect(result.findings[0]?.explanation).toContain('PRIVATE_ADDRESS');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('never throws when the fetch itself fails after validation succeeds', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockRejectedValueOnce(new Error('ECONNRESET'));

    const result = await scanHeaders('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.status).toBe('fail');
  });

  it('flags (without crashing or hanging) a GET that unexpectedly redirects after HEAD-based validation said it would not', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockResolvedValueOnce({
      statusCode: 302,
      headers: baseHeaders(),
      bodyBytesRead: 0,
      bodyTruncated: false,
    });

    const result = await scanHeaders('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    const warning = result.findings.find((f) => f.id === 'headers.unexpected-redirect');
    expect(warning?.status).toBe('warning');
    // The rest of the (intermediate response's) headers are still evaluated and reported.
    expect(result.findings.some((f) => f.id === 'headers.csp')).toBe(true);
  });

  it('evaluates cookies from the response using the final URL scheme', async () => {
    mockValidate.mockResolvedValueOnce({ ...VALIDATED, finalUrl: 'http://example.com/' });
    mockFetch.mockResolvedValueOnce({
      statusCode: 200,
      headers: { ...baseHeaders(), 'set-cookie': 'a=b; HttpOnly; SameSite=Strict' },
      bodyBytesRead: 0,
      bodyTruncated: false,
    });

    const result = await scanHeaders('http://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    const cookie = result.findings.find((f) => f.id === 'cookie.a');
    // Final URL is http, not https, so a missing Secure flag isn't penalized.
    expect(cookie?.status).not.toBe('fail');
  });
});
