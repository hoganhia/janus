import rateLimit from '@fastify/rate-limit';
import type { ScanJobData, ScanJobLike, ScanJobResult, ScanQueueLike } from '@janus/workers';
import { findDomainByName, recordScanConsent, type Domain } from '@janus/db';
import { validateScanTarget } from '@janus/shared';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { scanRoutes } from './scans.js';

vi.mock('@janus/shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/shared')>();
  return { ...actual, validateScanTarget: vi.fn() };
});

vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return { ...actual, findDomainByName: vi.fn(), recordScanConsent: vi.fn() };
});

const mockValidate = vi.mocked(validateScanTarget);
const mockFindDomainByName = vi.mocked(findDomainByName);
const mockRecordScanConsent = vi.mocked(recordScanConsent);

const SCANNER_USER_AGENT = 'JanusSecurityScanner/1.0 (+https://example.com/about-scans)';

function fakeJob(overrides: Partial<ScanJobLike> = {}): ScanJobLike {
  return {
    id: 'job-1',
    data: {
      targetUrl: 'https://example.com/',
      requesterIp: '127.0.0.1',
      userAgent: SCANNER_USER_AGENT,
    },
    getState: vi.fn().mockResolvedValue('waiting'),
    returnvalue: undefined as unknown as ScanJobResult,
    failedReason: '',
    ...overrides,
  };
}

class FakeScanQueue implements ScanQueueLike {
  jobs = new Map<string, ScanJobLike>();
  addedData: ScanJobData[] = [];

  add = vi.fn((_name: string, data: ScanJobData) => {
    this.addedData.push(data);
    const job = fakeJob({ id: `job-${String(this.addedData.length)}`, data });
    this.jobs.set(job.id ?? '', job);
    return Promise.resolve(job as never);
  });

  getJob = vi.fn((jobId: string) => Promise.resolve(this.jobs.get(jobId)));
}

async function buildTestApp(scanQueue: ScanQueueLike): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(rateLimit, { max: 1000, timeWindow: 60_000 });
  app.setValidatorCompiler(validatorCompiler);
  // See the matching eslint-disable comment in app.ts — known type-friction, not a real issue.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  app.setSerializerCompiler(serializerCompiler);
  await app.register(scanRoutes, { scanQueue, scannerUserAgent: SCANNER_USER_AGENT });
  await app.ready();
  return app;
}

describe('scanRoutes', () => {
  let queue: FakeScanQueue;
  let app: FastifyInstance;

  afterEach(async () => {
    vi.resetAllMocks();
    await app.close();
  });

  describe('POST /scans', () => {
    it('validates the target, enqueues a job with no auth required, and returns 202 with a jobId', async () => {
      queue = new FakeScanQueue();
      mockValidate.mockResolvedValue({
        requestedUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        pinnedAddress: '93.184.216.34',
        family: 4,
        redirectCount: 0,
      });
      app = await buildTestApp(queue);

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://example.com/', attestation: true },
      });

      expect(response.statusCode).toBe(202);
      const body = response.json<{ jobId: string; targetUrl: string }>();
      expect(body.targetUrl).toBe('https://example.com/');
      expect(body.jobId).toBeTruthy();
      expect(queue.addedData).toHaveLength(1);
      expect(queue.addedData[0]).toMatchObject({
        targetUrl: 'https://example.com/',
        userAgent: SCANNER_USER_AGENT,
      });
    });

    it('records a ScanConsent row for the attestation before enqueueing', async () => {
      queue = new FakeScanQueue();
      mockValidate.mockResolvedValue({
        requestedUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        pinnedAddress: '93.184.216.34',
        family: 4,
        redirectCount: 0,
      });
      app = await buildTestApp(queue);

      await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://example.com/', attestation: true },
      });

      expect(mockRecordScanConsent).toHaveBeenCalledWith({
        userId: null,
        requesterIp: '127.0.0.1',
        targetDomain: 'example.com',
      });
    });

    it('rejects a submission missing attestation with 400, without validating, enqueueing, or recording consent', async () => {
      queue = new FakeScanQueue();
      app = await buildTestApp(queue);

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://example.com/' },
      });

      expect(response.statusCode).toBe(400);
      expect(mockValidate).not.toHaveBeenCalled();
      expect(queue.add).not.toHaveBeenCalled();
      expect(mockRecordScanConsent).not.toHaveBeenCalled();
    });

    it('rejects a submission with attestation: false with 400', async () => {
      queue = new FakeScanQueue();
      app = await buildTestApp(queue);

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://example.com/', attestation: false },
      });

      expect(response.statusCode).toBe(400);
      expect(queue.add).not.toHaveBeenCalled();
    });

    it('rejects a malformed URL with 400 before ever validating or enqueueing', async () => {
      queue = new FakeScanQueue();
      app = await buildTestApp(queue);

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'not a url', attestation: true },
      });

      expect(response.statusCode).toBe(400);
      expect(mockValidate).not.toHaveBeenCalled();
      expect(queue.add).not.toHaveBeenCalled();
    });

    it('rejects a target validateScanTarget rejects, with 400, without enqueueing', async () => {
      queue = new FakeScanQueue();
      const { ScanTargetRejectedError } =
        await vi.importActual<typeof import('@janus/shared')>('@janus/shared');
      mockValidate.mockRejectedValue(
        new ScanTargetRejectedError('PRIVATE_ADDRESS', 'Target must resolve to a public address'),
      );
      app = await buildTestApp(queue);

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://internal.example.com/', attestation: true },
      });

      expect(response.statusCode).toBe(400);
      expect(queue.add).not.toHaveBeenCalled();
      expect(mockRecordScanConsent).not.toHaveBeenCalled();
    });

    it('propagates an unexpected validation error as a 500, without enqueueing', async () => {
      queue = new FakeScanQueue();
      mockValidate.mockRejectedValue(new Error('unexpected'));
      app = await buildTestApp(queue);

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://example.com/', attestation: true },
      });

      expect(response.statusCode).toBe(500);
      expect(queue.add).not.toHaveBeenCalled();
    });

    it('looks up the target domain and does not skip the opt-out check when it is unverified', async () => {
      queue = new FakeScanQueue();
      mockFindDomainByName.mockResolvedValue(null);
      mockValidate.mockResolvedValue({
        requestedUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        pinnedAddress: '93.184.216.34',
        family: 4,
        redirectCount: 0,
      });
      app = await buildTestApp(queue);

      await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://example.com/', attestation: true },
      });

      expect(mockFindDomainByName).toHaveBeenCalledWith('example.com');
      expect(mockValidate).toHaveBeenCalledWith(
        'https://example.com/',
        expect.objectContaining({ skipOptOutCheck: false }),
      );
    });

    it('skips the opt-out check when the target domain is AUTHENTICATED (verified owner)', async () => {
      queue = new FakeScanQueue();
      mockFindDomainByName.mockResolvedValue({ scanTier: 'AUTHENTICATED' } as Domain);
      mockValidate.mockResolvedValue({
        requestedUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        pinnedAddress: '93.184.216.34',
        family: 4,
        redirectCount: 0,
      });
      app = await buildTestApp(queue);

      await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://example.com/', attestation: true },
      });

      expect(mockValidate).toHaveBeenCalledWith(
        'https://example.com/',
        expect.objectContaining({ skipOptOutCheck: true }),
      );
    });

    it('rejects an opted-out target with 403, without enqueueing', async () => {
      queue = new FakeScanQueue();
      mockFindDomainByName.mockResolvedValue(null);
      const { ScanTargetRejectedError } =
        await vi.importActual<typeof import('@janus/shared')>('@janus/shared');
      mockValidate.mockRejectedValue(
        new ScanTargetRejectedError('OPTED_OUT', 'Target has opted out of scanning'),
      );
      app = await buildTestApp(queue);

      const response = await app.inject({
        method: 'POST',
        url: '/scans',
        payload: { targetUrl: 'https://opted-out.example.com/', attestation: true },
      });

      expect(response.statusCode).toBe(403);
      expect(queue.add).not.toHaveBeenCalled();
    });

    it('returns 429 after exceeding the per-IP hourly submission limit', async () => {
      queue = new FakeScanQueue();
      mockValidate.mockResolvedValue({
        requestedUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        pinnedAddress: '93.184.216.34',
        family: 4,
        redirectCount: 0,
      });
      app = await buildTestApp(queue);

      const statusCodes: number[] = [];
      for (let i = 0; i < 6; i++) {
        const response = await app.inject({
          method: 'POST',
          url: '/scans',
          payload: { targetUrl: 'https://example.com/', attestation: true },
        });
        statusCodes.push(response.statusCode);
      }

      expect(statusCodes.slice(0, 5)).toEqual([202, 202, 202, 202, 202]);
      expect(statusCodes[5]).toBe(429);
    });
  });

  describe('GET /scans/:id', () => {
    it('requires no authentication', async () => {
      queue = new FakeScanQueue();
      queue.jobs.set(
        'job-1',
        fakeJob({ id: 'job-1', getState: vi.fn().mockResolvedValue('active') }),
      );
      app = await buildTestApp(queue);

      // No Authorization header at all.
      const response = await app.inject({ method: 'GET', url: '/scans/job-1' });

      expect(response.statusCode).toBe(200);
    });

    it('returns 404 for an unknown job ID', async () => {
      queue = new FakeScanQueue();
      app = await buildTestApp(queue);

      const response = await app.inject({ method: 'GET', url: '/scans/does-not-exist' });

      expect(response.statusCode).toBe(404);
    });

    it('returns the bare status for a non-terminal job', async () => {
      queue = new FakeScanQueue();
      queue.jobs.set(
        'job-1',
        fakeJob({ id: 'job-1', getState: vi.fn().mockResolvedValue('active') }),
      );
      app = await buildTestApp(queue);

      const response = await app.inject({ method: 'GET', url: '/scans/job-1' });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ jobId: 'job-1', status: 'active' });
    });

    it('includes the result for a completed job', async () => {
      queue = new FakeScanQueue();
      const result: ScanJobResult = {
        domain: 'example.com',
        scanReportId: 'report-1',
        overallScore: 88,
        overallGrade: 'B',
      };
      queue.jobs.set(
        'job-1',
        fakeJob({
          id: 'job-1',
          getState: vi.fn().mockResolvedValue('completed'),
          returnvalue: result,
        }),
      );
      app = await buildTestApp(queue);

      const response = await app.inject({ method: 'GET', url: '/scans/job-1' });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ jobId: 'job-1', status: 'completed', result });
    });

    it('includes the failedReason for a failed job', async () => {
      queue = new FakeScanQueue();
      queue.jobs.set(
        'job-1',
        fakeJob({
          id: 'job-1',
          getState: vi.fn().mockResolvedValue('failed'),
          failedReason: 'Scan target rejected (PRIVATE_ADDRESS): nope',
        }),
      );
      app = await buildTestApp(queue);

      const response = await app.inject({ method: 'GET', url: '/scans/job-1' });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        jobId: 'job-1',
        status: 'failed',
        failedReason: 'Scan target rejected (PRIVATE_ADDRESS): nope',
      });
    });
  });
});
