import { getScanReportById, type Domain, type ScanReportWithDomain } from '@janus/db';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { scanReportRoutes } from './scan-reports.js';

vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return { ...actual, getScanReportById: vi.fn() };
});

const mockGetById = vi.mocked(getScanReportById);

function fakeDomain(overrides: Partial<Domain> = {}): Domain {
  return {
    id: 'domain-1',
    domain: 'example.com',
    verificationStatus: 'UNVERIFIED',
    verificationMethod: null,
    verificationToken: null,
    verifiedAt: null,
    verificationExpiresAt: null,
    scanTier: 'PASSIVE',
    createdAt: new Date('2026-07-13T00:00:00.000Z'),
    updatedAt: new Date('2026-07-13T00:00:00.000Z'),
    ...overrides,
  };
}

function fakeReport(overrides: Partial<ScanReportWithDomain> = {}): ScanReportWithDomain {
  return {
    id: 'report-1',
    domainId: 'domain-1',
    scannedAt: new Date('2026-07-13T00:00:00.000Z'),
    rawResults: { tls: { findings: [] } },
    computedScore: { overallScore: 88, overallGrade: 'B', categories: [] },
    overallGrade: 'B',
    overallScore: 88,
    createdAt: new Date('2026-07-13T00:00:01.000Z'),
    domain: fakeDomain(),
    ...overrides,
  };
}

async function buildTestApp(): Promise<FastifyInstance> {
  const app = Fastify();
  app.setValidatorCompiler(validatorCompiler);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  app.setSerializerCompiler(serializerCompiler);
  await app.register(scanReportRoutes);
  await app.ready();
  return app;
}

describe('scanReportRoutes', () => {
  let app: FastifyInstance;

  afterEach(async () => {
    vi.resetAllMocks();
    await app.close();
  });

  it('returns the full report, including the domain name, for a known ID', async () => {
    mockGetById.mockResolvedValue(fakeReport());
    app = await buildTestApp();

    const response = await app.inject({ method: 'GET', url: '/scan-reports/report-1' });

    expect(response.statusCode).toBe(200);
    expect(mockGetById).toHaveBeenCalledWith('report-1');
    expect(response.json()).toEqual({
      id: 'report-1',
      domain: 'example.com',
      scannedAt: '2026-07-13T00:00:00.000Z',
      overallScore: 88,
      overallGrade: 'B',
      rawResults: { tls: { findings: [] } },
      computedScore: { overallScore: 88, overallGrade: 'B', categories: [] },
    });
  });

  it('returns 404 for an unknown report ID', async () => {
    mockGetById.mockResolvedValue(null);
    app = await buildTestApp();

    const response = await app.inject({ method: 'GET', url: '/scan-reports/does-not-exist' });

    expect(response.statusCode).toBe(404);
  });

  it('requires no authentication', async () => {
    mockGetById.mockResolvedValue(fakeReport());
    app = await buildTestApp();

    const response = await app.inject({ method: 'GET', url: '/scan-reports/report-1' });

    expect(response.statusCode).toBe(200);
  });
});
