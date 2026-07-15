import { downgradeExpiredVerification, findExpiredVerifications, type Domain } from '@janus/db';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { expireStaleDomainVerifications } from './expire-domains.js';

vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return {
    ...actual,
    findExpiredVerifications: vi.fn(),
    downgradeExpiredVerification: vi.fn(),
  };
});

const mockFindExpired = vi.mocked(findExpiredVerifications);
const mockDowngrade = vi.mocked(downgradeExpiredVerification);

const NOW = new Date('2026-07-14T00:00:00.000Z');

function domain(overrides: Partial<Domain> = {}): Domain {
  return {
    id: 'domain-1',
    domain: 'example.com',
    verificationStatus: 'VERIFIED',
    verificationMethod: 'DNS_TXT',
    verificationToken: 'abc123',
    verifiedAt: new Date('2026-04-01T00:00:00.000Z'),
    verificationExpiresAt: new Date('2026-06-30T00:00:00.000Z'),
    scanTier: 'AUTHENTICATED',
    createdAt: new Date('2026-04-01T00:00:00.000Z'),
    updatedAt: new Date('2026-04-01T00:00:00.000Z'),
    ...overrides,
  };
}

describe('expireStaleDomainVerifications', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('returns zero expired when there are no candidates', async () => {
    mockFindExpired.mockResolvedValue([]);

    const result = await expireStaleDomainVerifications(NOW);

    expect(result).toEqual({ checkedAt: NOW.toISOString(), expiredCount: 0, domains: [] });
    expect(mockDowngrade).not.toHaveBeenCalled();
  });

  it('passes the provided now through to findExpiredVerifications', async () => {
    mockFindExpired.mockResolvedValue([]);

    await expireStaleDomainVerifications(NOW);

    expect(mockFindExpired).toHaveBeenCalledWith(NOW);
  });

  it('downgrades every expired candidate and reports their domain names', async () => {
    mockFindExpired.mockResolvedValue([
      domain({ id: 'd1', domain: 'a.example' }),
      domain({ id: 'd2', domain: 'b.example' }),
    ]);
    mockDowngrade.mockResolvedValue(domain());

    const result = await expireStaleDomainVerifications(NOW);

    expect(mockDowngrade).toHaveBeenCalledWith('d1');
    expect(mockDowngrade).toHaveBeenCalledWith('d2');
    expect(result.expiredCount).toBe(2);
    expect(result.domains).toEqual(['a.example', 'b.example']);
  });

  it('does not let one failed downgrade stop the others', async () => {
    mockFindExpired.mockResolvedValue([
      domain({ id: 'd1', domain: 'a.example' }),
      domain({ id: 'd2', domain: 'b.example' }),
      domain({ id: 'd3', domain: 'c.example' }),
    ]);
    mockDowngrade.mockImplementation((id: string) => {
      if (id === 'd2') return Promise.reject(new Error('db hiccup'));
      return Promise.resolve(domain());
    });

    const result = await expireStaleDomainVerifications(NOW);

    expect(result.expiredCount).toBe(2);
    expect(result.domains).toEqual(['a.example', 'c.example']);
  });

  it('throws only when every candidate fails to downgrade', async () => {
    mockFindExpired.mockResolvedValue([
      domain({ id: 'd1', domain: 'a.example' }),
      domain({ id: 'd2', domain: 'b.example' }),
    ]);
    mockDowngrade.mockRejectedValue(new Error('Postgres unreachable'));

    await expect(expireStaleDomainVerifications(NOW)).rejects.toThrow(
      /Failed to downgrade all 2 expired domain verifications/,
    );
  });

  it('defaults now to the current time when not provided', async () => {
    mockFindExpired.mockResolvedValue([]);
    const before = Date.now();

    const result = await expireStaleDomainVerifications();

    const after = Date.now();
    const checkedAtMs = new Date(result.checkedAt).getTime();
    expect(checkedAtMs).toBeGreaterThanOrEqual(before);
    expect(checkedAtMs).toBeLessThanOrEqual(after);
  });
});
