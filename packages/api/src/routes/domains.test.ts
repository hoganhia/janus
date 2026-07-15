import { findDomainByName, getScanReportHistory, type Domain, type ScanReport } from '@janus/db';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { domainRoutes } from './domains.js';

vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return { ...actual, getScanReportHistory: vi.fn(), findDomainByName: vi.fn() };
});

const mockGetHistory = vi.mocked(getScanReportHistory);
const mockFindDomain = vi.mocked(findDomainByName);

function fakeScanReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    id: 'report-1',
    domainId: 'domain-1',
    scannedAt: new Date('2026-07-13T00:00:00.000Z'),
    rawResults: { tls: { findings: [] } },
    computedScore: { overallScore: 88, overallGrade: 'B' },
    overallGrade: 'B',
    overallScore: 88,
    createdAt: new Date('2026-07-13T00:00:01.000Z'),
    ...overrides,
  };
}

function fakeDomain(overrides: Partial<Domain> = {}): Domain {
  return {
    id: 'domain-1',
    domain: 'example.com',
    verificationStatus: 'VERIFIED',
    verificationMethod: 'DNS_TXT',
    verificationToken: 'super-secret-token',
    verifiedAt: new Date('2026-04-01T00:00:00.000Z'),
    verificationExpiresAt: new Date('2026-06-30T00:00:00.000Z'),
    scanTier: 'AUTHENTICATED',
    createdAt: new Date('2026-04-01T00:00:00.000Z'),
    updatedAt: new Date('2026-04-01T00:00:00.000Z'),
    ...overrides,
  };
}

async function buildTestApp(): Promise<FastifyInstance> {
  const app = Fastify();
  app.setValidatorCompiler(validatorCompiler);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  app.setSerializerCompiler(serializerCompiler);
  await app.register(domainRoutes);
  await app.ready();
  return app;
}

describe('domainRoutes', () => {
  let app: FastifyInstance;

  afterEach(async () => {
    vi.resetAllMocks();
    await app.close();
  });

  it('returns scan history for a valid domain with the default limit', async () => {
    mockGetHistory.mockResolvedValue([fakeScanReport()]);
    app = await buildTestApp();

    const response = await app.inject({ method: 'GET', url: '/domains/example.com/history' });

    expect(response.statusCode).toBe(200);
    expect(mockGetHistory).toHaveBeenCalledWith('example.com', { limit: 20 });
    expect(response.json()).toEqual({
      domain: 'example.com',
      scans: [
        {
          id: 'report-1',
          scannedAt: '2026-07-13T00:00:00.000Z',
          overallScore: 88,
          overallGrade: 'B',
          rawResults: { tls: { findings: [] } },
          computedScore: { overallScore: 88, overallGrade: 'B' },
        },
      ],
    });
  });

  it('passes a custom limit through from the query string', async () => {
    mockGetHistory.mockResolvedValue([]);
    app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/domains/example.com/history?limit=5',
    });

    expect(response.statusCode).toBe(200);
    expect(mockGetHistory).toHaveBeenCalledWith('example.com', { limit: 5 });
  });

  it('rejects a limit above the max with 400', async () => {
    app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/domains/example.com/history?limit=51',
    });

    expect(response.statusCode).toBe(400);
    expect(mockGetHistory).not.toHaveBeenCalled();
  });

  it('rejects a malformed domain with 400', async () => {
    app = await buildTestApp();

    const response = await app.inject({ method: 'GET', url: '/domains/not a domain/history' });

    expect(response.statusCode).toBe(400);
    expect(mockGetHistory).not.toHaveBeenCalled();
  });

  it('returns an empty scans array for a domain with no history, without erroring', async () => {
    mockGetHistory.mockResolvedValue([]);
    app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/domains/never-scanned.example/history',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ domain: 'never-scanned.example', scans: [] });
  });

  it('requires no authentication', async () => {
    mockGetHistory.mockResolvedValue([]);
    app = await buildTestApp();

    // No Authorization header at all.
    const response = await app.inject({ method: 'GET', url: '/domains/example.com/history' });

    expect(response.statusCode).toBe(200);
  });

  describe('GET /domains/:domain/verification', () => {
    it('returns UNVERIFIED/PASSIVE defaults for a domain never seen before, without erroring', async () => {
      mockFindDomain.mockResolvedValue(null);
      app = await buildTestApp();

      const response = await app.inject({
        method: 'GET',
        url: '/domains/never-verified.example/verification',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        domain: 'never-verified.example',
        status: 'UNVERIFIED',
        method: null,
        scanTier: 'PASSIVE',
        verifiedAt: null,
        verificationExpiresAt: null,
      });
    });

    it('returns the current status/tier for a verified domain', async () => {
      mockFindDomain.mockResolvedValue(fakeDomain());
      app = await buildTestApp();

      const response = await app.inject({
        method: 'GET',
        url: '/domains/example.com/verification',
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        domain: 'example.com',
        status: 'VERIFIED',
        method: 'DNS_TXT',
        scanTier: 'AUTHENTICATED',
        verifiedAt: '2026-04-01T00:00:00.000Z',
        verificationExpiresAt: '2026-06-30T00:00:00.000Z',
      });
    });

    it('never includes the verification token in the response', async () => {
      mockFindDomain.mockResolvedValue(fakeDomain());
      app = await buildTestApp();

      const response = await app.inject({
        method: 'GET',
        url: '/domains/example.com/verification',
      });

      expect(JSON.stringify(response.json())).not.toContain('super-secret-token');
    });

    it('requires no authentication', async () => {
      mockFindDomain.mockResolvedValue(null);
      app = await buildTestApp();

      const response = await app.inject({
        method: 'GET',
        url: '/domains/example.com/verification',
      });

      expect(response.statusCode).toBe(200);
    });
  });
});
