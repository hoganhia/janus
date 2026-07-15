import { fetchPinned, validateScanTarget, type ValidatedScanTarget } from '@janus/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkWellKnownFileChallenge } from './well-known-challenge.js';

vi.mock('@janus/shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/shared')>();
  return { ...actual, validateScanTarget: vi.fn(), fetchPinned: vi.fn() };
});

const mockValidate = vi.mocked(validateScanTarget);
const mockFetch = vi.mocked(fetchPinned);

const VALIDATED: ValidatedScanTarget = {
  requestedUrl: 'https://example.com/.well-known/janus-verify.txt',
  finalUrl: 'https://example.com/.well-known/janus-verify.txt',
  pinnedAddress: '93.184.216.34',
  family: 4,
  redirectCount: 0,
};

const OPTIONS = { requesterIp: '203.0.113.9', userAgent: 'UA/1.0' };

function emptyResponse(overrides: Partial<Awaited<ReturnType<typeof fetchPinned>>> = {}) {
  return { statusCode: 404, headers: {}, bodyBytesRead: 0, bodyTruncated: false, ...overrides };
}

describe('checkWellKnownFileChallenge', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('validates the well-known URL for the domain, through validateScanTarget', async () => {
    mockValidate.mockResolvedValue(VALIDATED);
    mockFetch.mockResolvedValue(emptyResponse({ statusCode: 200, body: Buffer.from('abc123') }));

    await checkWellKnownFileChallenge('example.com', 'abc123', OPTIONS);

    expect(mockValidate).toHaveBeenCalledWith(
      'https://example.com/.well-known/janus-verify.txt',
      expect.objectContaining({ requesterIp: OPTIONS.requesterIp, userAgent: OPTIONS.userAgent }),
    );
  });

  it('fetches the validated/pinned final URL, not the raw request URL', async () => {
    mockValidate.mockResolvedValue({
      ...VALIDATED,
      finalUrl: 'https://www.example.com/.well-known/janus-verify.txt',
      pinnedAddress: '1.2.3.4',
    });
    mockFetch.mockResolvedValue(emptyResponse({ statusCode: 200, body: Buffer.from('abc123') }));

    await checkWellKnownFileChallenge('example.com', 'abc123', OPTIONS);

    const [urlArg, addressArg] = mockFetch.mock.calls[0] ?? [];
    expect(urlArg?.toString()).toBe('https://www.example.com/.well-known/janus-verify.txt');
    expect(addressArg).toBe('1.2.3.4');
  });

  it('returns true when the response is 200 and the body exactly matches the token', async () => {
    mockValidate.mockResolvedValue(VALIDATED);
    mockFetch.mockResolvedValue(emptyResponse({ statusCode: 200, body: Buffer.from('abc123') }));

    const result = await checkWellKnownFileChallenge('example.com', 'abc123', OPTIONS);

    expect(result).toBe(true);
  });

  it('trims surrounding whitespace/newlines from the file content before comparing', async () => {
    mockValidate.mockResolvedValue(VALIDATED);
    mockFetch.mockResolvedValue(
      emptyResponse({ statusCode: 200, body: Buffer.from('  abc123\n') }),
    );

    const result = await checkWellKnownFileChallenge('example.com', 'abc123', OPTIONS);

    expect(result).toBe(true);
  });

  it('returns false when the file content does not match the token', async () => {
    mockValidate.mockResolvedValue(VALIDATED);
    mockFetch.mockResolvedValue(
      emptyResponse({ statusCode: 200, body: Buffer.from('not-the-token') }),
    );

    const result = await checkWellKnownFileChallenge('example.com', 'abc123', OPTIONS);

    expect(result).toBe(false);
  });

  it('returns false when the file does not exist (404)', async () => {
    mockValidate.mockResolvedValue(VALIDATED);
    mockFetch.mockResolvedValue(emptyResponse({ statusCode: 404 }));

    const result = await checkWellKnownFileChallenge('example.com', 'abc123', OPTIONS);

    expect(result).toBe(false);
  });

  it('returns false (not a throw) when validateScanTarget rejects the target', async () => {
    const { ScanTargetRejectedError } =
      await vi.importActual<typeof import('@janus/shared')>('@janus/shared');
    mockValidate.mockRejectedValue(
      new ScanTargetRejectedError('PRIVATE_ADDRESS', 'Target must resolve to a public address'),
    );

    const result = await checkWellKnownFileChallenge('example.com', 'abc123', OPTIONS);

    expect(result).toBe(false);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('returns false (not a throw) when the fetch itself fails', async () => {
    mockValidate.mockResolvedValue(VALIDATED);
    mockFetch.mockRejectedValue(new Error('ECONNRESET'));

    const result = await checkWellKnownFileChallenge('example.com', 'abc123', OPTIONS);

    expect(result).toBe(false);
  });
});
