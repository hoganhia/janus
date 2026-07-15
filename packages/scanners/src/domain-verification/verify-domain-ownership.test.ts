import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkDnsTxtChallenge } from './dns-challenge.js';
import { verifyDomainOwnership } from './verify-domain-ownership.js';
import { checkWellKnownFileChallenge } from './well-known-challenge.js';

vi.mock('./dns-challenge.js', () => ({ checkDnsTxtChallenge: vi.fn() }));
vi.mock('./well-known-challenge.js', () => ({ checkWellKnownFileChallenge: vi.fn() }));

const mockDnsCheck = vi.mocked(checkDnsTxtChallenge);
const mockFileCheck = vi.mocked(checkWellKnownFileChallenge);

const OPTIONS = { requesterIp: '203.0.113.9', userAgent: 'UA/1.0' };

describe('verifyDomainOwnership', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('dispatches to the DNS TXT check for method DNS_TXT', async () => {
    mockDnsCheck.mockResolvedValue(true);

    const result = await verifyDomainOwnership('example.com', 'DNS_TXT', 'abc123', OPTIONS);

    expect(result).toBe(true);
    expect(mockDnsCheck).toHaveBeenCalledWith('example.com', 'abc123', OPTIONS);
    expect(mockFileCheck).not.toHaveBeenCalled();
  });

  it('dispatches to the well-known file check for method WELL_KNOWN_FILE', async () => {
    mockFileCheck.mockResolvedValue(false);

    const result = await verifyDomainOwnership('example.com', 'WELL_KNOWN_FILE', 'abc123', OPTIONS);

    expect(result).toBe(false);
    expect(mockFileCheck).toHaveBeenCalledWith('example.com', 'abc123', OPTIONS);
    expect(mockDnsCheck).not.toHaveBeenCalled();
  });
});
