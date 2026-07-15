import dns from 'node:dns/promises';
import type { Logger } from 'pino';
import { afterEach, describe, expect, it, vi, type Mock } from 'vitest';
import { probePinned } from './pinned-request.js';
import { InMemoryScanTargetListStore } from './scan-target-list-store.js';
import { validateScanTarget } from './validate-scan-target.js';

vi.mock('node:dns/promises', () => {
  const lookup = vi.fn();
  return { default: { lookup }, lookup };
});
vi.mock('./pinned-request.js', () => ({ probePinned: vi.fn() }));

// dns.lookup is heavily overloaded (single result vs. array, depending on the `all` option);
// the mock is only ever driven with the `{ all: true }` shape resolvePublicAddress actually uses.
const mockLookup = dns.lookup as unknown as Mock;
const mockProbePinned = vi.mocked(probePinned);

function fakeLogger(): Logger {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn() } as unknown as Logger;
}

async function rejectionReason(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (err) {
    if (err && typeof err === 'object' && 'reason' in err) return String(err.reason);
    throw err;
  }
  throw new Error('expected promise to reject');
}

describe('validateScanTarget', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('rejects a malformed URL before any network activity', async () => {
    const reason = await rejectionReason(
      validateScanTarget('not a url', { requesterIp: '203.0.113.9', logger: fakeLogger() }),
    );
    expect(reason).toBe('MALFORMED_URL');
    expect(mockProbePinned).not.toHaveBeenCalled();
  });

  it('rejects non-http(s) protocols', async () => {
    const reason = await rejectionReason(
      validateScanTarget('file:///etc/passwd', {
        requesterIp: '203.0.113.9',
        logger: fakeLogger(),
      }),
    );
    expect(reason).toBe('UNSUPPORTED_PROTOCOL');
  });

  it('rejects URLs containing credentials', async () => {
    const reason = await rejectionReason(
      validateScanTarget('http://user:pass@example.com/', {
        requesterIp: '203.0.113.9',
        logger: fakeLogger(),
      }),
    );
    expect(reason).toBe('CREDENTIALS_IN_URL');
  });

  it.each(['http://localhost/', 'http://foo.local/', 'http://foo.internal/'])(
    'rejects blocked hostname %s',
    async (url) => {
      const reason = await rejectionReason(
        validateScanTarget(url, { requesterIp: '203.0.113.9', logger: fakeLogger() }),
      );
      expect(reason).toBe('BLOCKED_HOSTNAME');
    },
  );

  it('rejects a hostname on the deny list before resolving DNS', async () => {
    const listStore = new InMemoryScanTargetListStore({ denied: ['blocked.example'] });
    const reason = await rejectionReason(
      validateScanTarget('http://blocked.example/', {
        requesterIp: '203.0.113.9',
        logger: fakeLogger(),
        listStore,
      }),
    );
    expect(reason).toBe('DENIED_BY_LIST');
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('rejects a hostname not on a configured allow list', async () => {
    const listStore = new InMemoryScanTargetListStore({ allowed: ['good.example'] });
    const reason = await rejectionReason(
      validateScanTarget('http://other.example/', {
        requesterIp: '203.0.113.9',
        logger: fakeLogger(),
        listStore,
      }),
    );
    expect(reason).toBe('NOT_ALLOWLISTED');
  });

  describe('SSRF bypass attempts', () => {
    it('rejects a decimal-encoded loopback IP (http://2130706433/)', async () => {
      const reason = await rejectionReason(
        validateScanTarget('http://2130706433/', {
          requesterIp: '203.0.113.9',
          logger: fakeLogger(),
        }),
      );
      expect(reason).toBe('PRIVATE_ADDRESS');
      expect(mockProbePinned).not.toHaveBeenCalled();
    });

    it('rejects an IPv6 loopback target (http://[::1]/)', async () => {
      const reason = await rejectionReason(
        validateScanTarget('http://[::1]/', { requesterIp: '203.0.113.9', logger: fakeLogger() }),
      );
      expect(reason).toBe('PRIVATE_ADDRESS');
      expect(mockProbePinned).not.toHaveBeenCalled();
    });

    it('rejects a hostname that resolves to a private address', async () => {
      mockLookup.mockResolvedValueOnce([{ address: '10.0.0.5', family: 4 }]);
      const reason = await rejectionReason(
        validateScanTarget('http://internal-host.example/', {
          requesterIp: '203.0.113.9',
          logger: fakeLogger(),
        }),
      );
      expect(reason).toBe('PRIVATE_ADDRESS');
      expect(mockProbePinned).not.toHaveBeenCalled();
    });

    it('rejects a redirect chain that points at an internal IP, without ever probing it', async () => {
      mockLookup.mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }]);
      mockProbePinned.mockResolvedValueOnce({
        statusCode: 302,
        location: 'http://127.0.0.1:9999/admin',
      });

      const reason = await rejectionReason(
        validateScanTarget('http://redirector.example/', {
          requesterIp: '203.0.113.9',
          logger: fakeLogger(),
        }),
      );

      expect(reason).toBe('PRIVATE_ADDRESS');
      // Only the first (legitimate) hop was ever actually connected to.
      expect(mockProbePinned).toHaveBeenCalledTimes(1);
      expect(mockProbePinned).toHaveBeenCalledWith(expect.any(URL), '93.184.216.34', {});
    });

    it('gives up after exceeding the max redirect count instead of following forever', async () => {
      mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
      let hop = 0;
      mockProbePinned.mockImplementation(() => {
        hop += 1;
        return Promise.resolve({
          statusCode: 302,
          location: `http://redirector.example/${String(hop)}`,
        });
      });

      const reason = await rejectionReason(
        validateScanTarget('http://redirector.example/', {
          requesterIp: '203.0.113.9',
          logger: fakeLogger(),
          maxRedirects: 3,
        }),
      );

      expect(reason).toBe('TOO_MANY_REDIRECTS');
      // 1 initial hop + 3 followed redirects = 4 probes, the 4th response is the one that's refused.
      expect(mockProbePinned).toHaveBeenCalledTimes(4);
    });

    it('defeats DNS rebinding by pinning the first-resolved address and never re-resolving mid-request', async () => {
      // Simulate a hostname whose *next* lookup would return a private address — proving that
      // if validateScanTarget re-resolved before connecting, it would be exploitable.
      mockLookup
        .mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }])
        .mockResolvedValueOnce([{ address: '10.0.0.5', family: 4 }]);
      mockProbePinned.mockResolvedValueOnce({ statusCode: 200, location: undefined });

      const result = await validateScanTarget('http://rebind.example/', {
        requesterIp: '203.0.113.9',
        logger: fakeLogger(),
      });

      expect(result.pinnedAddress).toBe('93.184.216.34');
      expect(mockProbePinned).toHaveBeenCalledWith(expect.any(URL), '93.184.216.34', {});
      // Exactly one lookup for the whole request — the "second, rebound" answer above is never consulted.
      expect(mockLookup).toHaveBeenCalledTimes(1);
    });
  });

  it('follows a single legitimate redirect and validates the final target', async () => {
    mockLookup
      .mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }])
      .mockResolvedValueOnce([{ address: '104.16.132.229', family: 4 }]);
    mockProbePinned
      .mockResolvedValueOnce({ statusCode: 301, location: 'http://final.example/report' })
      .mockResolvedValueOnce({ statusCode: 200, location: undefined });

    const result = await validateScanTarget('http://redirector.example/', {
      requesterIp: '203.0.113.9',
      logger: fakeLogger(),
    });

    expect(result.finalUrl).toBe('http://final.example/report');
    expect(result.pinnedAddress).toBe('104.16.132.229');
    expect(result.redirectCount).toBe(1);
    expect(mockProbePinned).toHaveBeenCalledTimes(2);
  });

  it('logs every validation attempt, success and failure', async () => {
    const logger = fakeLogger();
    mockLookup.mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }]);
    mockProbePinned.mockResolvedValueOnce({ statusCode: 200, location: undefined });
    await validateScanTarget('http://good.example/', { requesterIp: '203.0.113.9', logger });
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ requesterIp: '203.0.113.9', targetUrl: 'http://good.example/' }),
      expect.any(String),
    );

    const failingLogger = fakeLogger();
    await rejectionReason(
      validateScanTarget('http://localhost/', {
        requesterIp: '203.0.113.9',
        logger: failingLogger,
      }),
    );
    expect(failingLogger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ requesterIp: '203.0.113.9', reason: 'BLOCKED_HOSTNAME' }),
      expect.any(String),
    );
  });
});
