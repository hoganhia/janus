import {
  fetchPinned,
  validateScanTarget,
  type ScanFinding,
  type ValidatedScanTarget,
} from '@janus/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildCveFindings } from './cve-matching.js';
import { fingerprintStack } from './scan-fingerprint.js';

vi.mock('@janus/shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/shared')>();
  return { ...actual, validateScanTarget: vi.fn(), fetchPinned: vi.fn() };
});
vi.mock('./cve-matching.js', () => ({ buildCveFindings: vi.fn() }));

const mockValidate = vi.mocked(validateScanTarget);
const mockFetch = vi.mocked(fetchPinned);
const mockBuildCveFindings = vi.mocked(buildCveFindings);

const VALIDATED: ValidatedScanTarget = {
  requestedUrl: 'https://example.com/',
  finalUrl: 'https://example.com/',
  pinnedAddress: '93.184.216.34',
  family: 4,
  redirectCount: 0,
};

function emptyResponse(overrides: Partial<Awaited<ReturnType<typeof fetchPinned>>> = {}) {
  return {
    statusCode: 404,
    headers: {},
    bodyBytesRead: 0,
    bodyTruncated: false,
    ...overrides,
  };
}

describe('fingerprintStack', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('detects a product from headers and includes its CVE findings', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockImplementation((url) => {
      if (url.toString() === 'https://example.com/') {
        return Promise.resolve(
          emptyResponse({ statusCode: 200, headers: { server: 'nginx/1.18.0' } }),
        );
      }
      return Promise.resolve(emptyResponse());
    });
    mockBuildCveFindings.mockResolvedValueOnce([
      {
        id: 'fingerprint.cve.CVE-2021-23017',
        label: 'CVE-2021-23017',
        status: 'fail',
        explanation: 'x',
      },
    ]);

    const result = await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    expect(result.caveat).toMatch(/probabilistic/i);
    const detected = result.findings.find((f) => f.id === 'fingerprint.detected.nginx');
    expect(detected?.explanation).toContain('nginx version 1.18.0');
    expect(result.findings.some((f) => f.id === 'fingerprint.cve.CVE-2021-23017')).toBe(true);
    expect(mockBuildCveFindings).toHaveBeenCalledWith('nginx', '1.18.0');
  });

  it('never throws when validation rejects the target', async () => {
    const { ScanTargetRejectedError } =
      await vi.importActual<typeof import('@janus/shared')>('@janus/shared');
    mockValidate.mockRejectedValueOnce(new ScanTargetRejectedError('PRIVATE_ADDRESS', 'nope'));

    const result = await fingerprintStack('http://internal.example/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.id).toBe('fingerprint.connection');
    expect(result.findings[0]?.status).toBe('fail');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('never throws when the main page fetch itself fails', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockRejectedValueOnce(new Error('ECONNRESET'));

    const result = await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.status).toBe('fail');
  });

  it('does not abort the scan when a single path check fails', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    let callCount = 0;
    mockFetch.mockImplementation((url) => {
      callCount++;
      if (url.toString() === 'https://example.com/') {
        return Promise.resolve(emptyResponse({ statusCode: 200 }));
      }
      if (url.toString().includes('wp-login.php')) {
        return Promise.reject(new Error('ECONNRESET'));
      }
      return Promise.resolve(emptyResponse());
    });

    const result = await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    // The scan as a whole still completes (doesn't come back as a single connection-failure
    // finding) even though one of the path checks threw.
    expect(result.findings.find((f) => f.id === 'fingerprint.connection')).toBeUndefined();
    expect(callCount).toBeGreaterThan(1);
  });

  it('merges header and path detections for the same product, preferring a found version', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockImplementation((url) => {
      const href = url.toString();
      if (href === 'https://example.com/')
        return Promise.resolve(emptyResponse({ statusCode: 200 }));
      if (href.includes('wp-login.php')) return Promise.resolve(emptyResponse({ statusCode: 200 }));
      if (href.includes('readme.html')) {
        return Promise.resolve(
          emptyResponse({ statusCode: 200, body: Buffer.from('<h2>Version 6.4.2</h2>') }),
        );
      }
      return Promise.resolve(emptyResponse());
    });
    mockBuildCveFindings.mockResolvedValueOnce([]);

    const result = await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    const detected = result.findings.find((f) => f.id === 'fingerprint.detected.wordpress');
    expect(detected?.explanation).toContain('WordPress version 6.4.2');
    expect((detected?.details as { sources: string[] } | undefined)?.sources).toEqual(
      expect.arrayContaining(['/wp-login.php', '/readme.html']),
    );
    expect(mockBuildCveFindings).toHaveBeenCalledWith('wordpress', '6.4.2');
  });

  it('reuses the same pinned address for every request — main page and every path check', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockResolvedValue(emptyResponse());

    await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    expect(mockFetch).toHaveBeenCalled();
    for (const call of mockFetch.mock.calls) {
      expect(call[1]).toBe('93.184.216.34');
    }
    // validateScanTarget should only be called once, not per path check.
    expect(mockValidate).toHaveBeenCalledTimes(1);
  });

  it('reports a product with no detectable version, and skips CVE lookup for it', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockImplementation((url) => {
      const href = url.toString();
      if (href.includes('wp-login.php')) return Promise.resolve(emptyResponse({ statusCode: 200 }));
      return Promise.resolve(emptyResponse());
    });

    const result = await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    const detected = result.findings.find((f) => f.id === 'fingerprint.detected.wordpress');
    expect(detected?.explanation).toContain('no version could be determined');
    expect(mockBuildCveFindings).not.toHaveBeenCalled();
  });

  it('reports the generic /vendor/ signal without treating it as a CVE-trackable product', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockImplementation((url) => {
      const href = url.toString();
      if (href.includes('/vendor/')) return Promise.resolve(emptyResponse({ statusCode: 200 }));
      return Promise.resolve(emptyResponse());
    });

    const result = await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    const vendorFinding: ScanFinding | undefined = result.findings.find(
      (f) => f.id === 'fingerprint.path./vendor/',
    );
    expect(vendorFinding?.status).toBe('warning');
    expect(mockBuildCveFindings).not.toHaveBeenCalled();
  });

  it('passes maxRedirects and userAgent through to validateScanTarget, defaulting maxRedirects to 3', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockResolvedValue(emptyResponse());

    await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    expect(mockValidate).toHaveBeenCalledWith(
      'https://example.com/',
      expect.objectContaining({ maxRedirects: 3, userAgent: 'UA/1.0' }),
    );
  });

  it('returns no product findings (just the caveat) when nothing is detected', async () => {
    mockValidate.mockResolvedValueOnce(VALIDATED);
    mockFetch.mockResolvedValue(emptyResponse());

    const result = await fingerprintStack('https://example.com/', {
      requesterIp: '203.0.113.9',
      userAgent: 'UA/1.0',
    });

    expect(result.findings).toEqual([]);
    expect(result.caveat.length).toBeGreaterThan(0);
  });
});
