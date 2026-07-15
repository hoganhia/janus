import { getAuth } from '@clerk/fastify';
import rateLimit from '@fastify/rate-limit';
import {
  findDomainByName,
  hasAcceptedLatestLegalVersion,
  markDomainVerificationFailed,
  markDomainVerified,
  startDomainVerification,
  type Domain,
} from '@janus/db';
import { verifyDomainOwnership } from '@janus/scanners';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { domainVerificationRoutes } from './domain-verification.js';

vi.mock('@clerk/fastify', () => ({ getAuth: vi.fn() }));
vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return {
    ...actual,
    startDomainVerification: vi.fn(),
    findDomainByName: vi.fn(),
    markDomainVerified: vi.fn(),
    markDomainVerificationFailed: vi.fn(),
    hasAcceptedLatestLegalVersion: vi.fn(),
  };
});
vi.mock('@janus/scanners', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/scanners')>();
  return { ...actual, verifyDomainOwnership: vi.fn() };
});

const mockGetAuth = vi.mocked(getAuth);
const mockStart = vi.mocked(startDomainVerification);
const mockFindDomain = vi.mocked(findDomainByName);
const mockMarkVerified = vi.mocked(markDomainVerified);
const mockMarkFailed = vi.mocked(markDomainVerificationFailed);
const mockVerifyOwnership = vi.mocked(verifyDomainOwnership);
const mockHasAccepted = vi.mocked(hasAcceptedLatestLegalVersion);

const SCANNER_USER_AGENT = 'JanusSecurityScanner/1.0 (+https://example.com/about-scans)';
const USER_ID = 'user_owner123';

function mockSignedIn(userId: string = USER_ID): void {
  mockGetAuth.mockReturnValue({ userId } as ReturnType<typeof getAuth>);
}
function mockSignedOut(): void {
  mockGetAuth.mockReturnValue({ userId: null } as ReturnType<typeof getAuth>);
}

function fakeDomain(overrides: Partial<Domain> = {}): Domain {
  return {
    id: 'domain-1',
    domain: 'example.com',
    verificationStatus: 'PENDING',
    verificationMethod: 'DNS_TXT',
    verificationToken: 'abc123',
    verifiedAt: null,
    verificationExpiresAt: null,
    scanTier: 'PASSIVE',
    createdAt: new Date('2026-07-14T00:00:00.000Z'),
    updatedAt: new Date('2026-07-14T00:00:00.000Z'),
    ...overrides,
  };
}

async function buildTestApp(): Promise<FastifyInstance> {
  const app = Fastify();
  // domainVerificationRoutes calls app.createRateLimit() at registration time, so
  // @fastify/rate-limit must be registered first, exactly as in the real app.
  await app.register(rateLimit, { max: 1000, timeWindow: 60_000 });
  app.setValidatorCompiler(validatorCompiler);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  app.setSerializerCompiler(serializerCompiler);
  await app.register(domainVerificationRoutes, { scannerUserAgent: SCANNER_USER_AGENT });
  await app.ready();
  return app;
}

describe('domainVerificationRoutes', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    mockSignedIn();
    // Every existing test in this file is exercising verification logic, not the ToS/AUP gate
    // itself — default to "already accepted" so requireLegalAcceptance doesn't 403 them. The
    // gate's own behavior is tested separately below.
    mockHasAccepted.mockResolvedValue(true);
  });

  afterEach(async () => {
    vi.resetAllMocks();
    await app.close();
  });

  describe('POST /domains/:domain/verification', () => {
    it('starts a DNS_TXT challenge and returns TXT record instructions', async () => {
      mockStart.mockResolvedValue(fakeDomain({ verificationMethod: 'DNS_TXT' }));
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification',
        payload: { method: 'DNS_TXT' },
      });

      expect(response.statusCode).toBe(200);
      expect(mockStart).toHaveBeenCalledWith('example.com', 'DNS_TXT', expect.any(String));
      const body = response.json<{
        domain: string;
        status: string;
        instructions: { method: string; recordName: string; recordType: string };
      }>();
      expect(body.status).toBe('PENDING');
      expect(body.instructions.method).toBe('DNS_TXT');
      expect(body.instructions.recordName).toBe('_janus-verify.example.com');
    });

    it('starts a WELL_KNOWN_FILE challenge and returns file instructions', async () => {
      mockStart.mockResolvedValue(fakeDomain({ verificationMethod: 'WELL_KNOWN_FILE' }));
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification',
        payload: { method: 'WELL_KNOWN_FILE' },
      });

      expect(response.statusCode).toBe(200);
      const body = response.json<{ instructions: { method: string; url: string } }>();
      expect(body.instructions.method).toBe('WELL_KNOWN_FILE');
      expect(body.instructions.url).toBe('https://example.com/.well-known/janus-verify.txt');
    });

    it('rejects an unauthenticated request with 401, without starting a challenge', async () => {
      mockSignedOut();
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification',
        payload: { method: 'DNS_TXT' },
      });

      expect(response.statusCode).toBe(401);
      expect(mockStart).not.toHaveBeenCalled();
    });

    it('rejects with 403 when the caller has not accepted the Terms of Service', async () => {
      mockHasAccepted.mockImplementation((_userId, documentType) =>
        Promise.resolve(documentType !== 'TERMS_OF_SERVICE'),
      );
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification',
        payload: { method: 'DNS_TXT' },
      });

      expect(response.statusCode).toBe(403);
      expect(mockStart).not.toHaveBeenCalled();
    });

    it('rejects with 403 when the caller has not accepted the Acceptable Use Policy', async () => {
      mockHasAccepted.mockImplementation((_userId, documentType) =>
        Promise.resolve(documentType !== 'ACCEPTABLE_USE_POLICY'),
      );
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification',
        payload: { method: 'DNS_TXT' },
      });

      expect(response.statusCode).toBe(403);
      expect(mockStart).not.toHaveBeenCalled();
    });

    it('rejects an unknown method with 400', async () => {
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification',
        payload: { method: 'CARRIER_PIGEON' },
      });

      expect(response.statusCode).toBe(400);
      expect(mockStart).not.toHaveBeenCalled();
    });
  });

  describe('POST /domains/:domain/verification/check', () => {
    it('marks the domain verified and unlocks the AUTHENTICATED tier on a matching challenge', async () => {
      mockFindDomain.mockResolvedValue(fakeDomain());
      mockVerifyOwnership.mockResolvedValue(true);
      mockMarkVerified.mockResolvedValue(
        fakeDomain({
          verificationStatus: 'VERIFIED',
          scanTier: 'AUTHENTICATED',
          verifiedAt: new Date('2026-07-14T00:00:00.000Z'),
          verificationExpiresAt: new Date('2026-10-12T00:00:00.000Z'),
        }),
      );
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification/check',
      });

      expect(response.statusCode).toBe(200);
      expect(mockMarkVerified).toHaveBeenCalledTimes(1);
      const [domainIdArg, verifyInput] = mockMarkVerified.mock.calls[0] ?? [];
      expect(domainIdArg).toBe('domain-1');
      expect(verifyInput?.verifiedAt).toBeInstanceOf(Date);
      expect(verifyInput?.expiresAt).toBeInstanceOf(Date);
      expect(mockMarkFailed).not.toHaveBeenCalled();
      const body = response.json<{ status: string; scanTier: string }>();
      expect(body.status).toBe('VERIFIED');
      expect(body.scanTier).toBe('AUTHENTICATED');
    });

    it('sets the expiry 90 days after verification', async () => {
      mockFindDomain.mockResolvedValue(fakeDomain());
      mockVerifyOwnership.mockResolvedValue(true);
      mockMarkVerified.mockResolvedValue(fakeDomain({ verificationStatus: 'VERIFIED' }));
      app = await buildTestApp();

      await app.inject({ method: 'POST', url: '/domains/example.com/verification/check' });

      const [, input] = mockMarkVerified.mock.calls[0] ?? [];
      const verifiedAt = input?.verifiedAt as Date;
      const expiresAt = input?.expiresAt as Date;
      const diffDays = (expiresAt.getTime() - verifiedAt.getTime()) / (24 * 60 * 60 * 1000);
      expect(diffDays).toBeCloseTo(90, 5);
    });

    it('marks the domain failed (not verified) when the challenge does not match', async () => {
      mockFindDomain.mockResolvedValue(fakeDomain());
      mockVerifyOwnership.mockResolvedValue(false);
      mockMarkFailed.mockResolvedValue(fakeDomain({ verificationStatus: 'FAILED' }));
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification/check',
      });

      expect(response.statusCode).toBe(200);
      expect(mockMarkFailed).toHaveBeenCalledWith('domain-1');
      expect(mockMarkVerified).not.toHaveBeenCalled();
      expect(response.json<{ status: string }>().status).toBe('FAILED');
    });

    it('returns 400 when no challenge has been started for the domain', async () => {
      mockFindDomain.mockResolvedValue(null);
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification/check',
      });

      expect(response.statusCode).toBe(400);
      expect(mockVerifyOwnership).not.toHaveBeenCalled();
    });

    it('returns 400 when the domain exists but has no token (never started)', async () => {
      mockFindDomain.mockResolvedValue(
        fakeDomain({ verificationToken: null, verificationMethod: null }),
      );
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification/check',
      });

      expect(response.statusCode).toBe(400);
      expect(mockVerifyOwnership).not.toHaveBeenCalled();
    });

    it('rejects an unauthenticated request with 401', async () => {
      mockSignedOut();
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/domains/example.com/verification/check',
      });

      expect(response.statusCode).toBe(401);
      expect(mockFindDomain).not.toHaveBeenCalled();
    });
  });
});
