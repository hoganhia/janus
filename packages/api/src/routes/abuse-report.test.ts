import rateLimit from '@fastify/rate-limit';
import { createAbuseReport, type AbuseReport } from '@janus/db';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { abuseReportRoutes } from './abuse-report.js';

vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return { ...actual, createAbuseReport: vi.fn() };
});

const mockCreate = vi.mocked(createAbuseReport);

function fakeReport(overrides: Partial<AbuseReport> = {}): AbuseReport {
  return {
    id: 'abuse-1',
    domain: 'example.com',
    reason: 'Too many requests',
    details: null,
    contact: null,
    createdAt: new Date('2026-07-15T00:00:00.000Z'),
    ...overrides,
  };
}

async function buildTestApp(): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(rateLimit, { max: 1000, timeWindow: 60_000 });
  app.setValidatorCompiler(validatorCompiler);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  app.setSerializerCompiler(serializerCompiler);
  await app.register(abuseReportRoutes);
  await app.ready();
  return app;
}

describe('abuseReportRoutes', () => {
  let app: FastifyInstance;

  afterEach(async () => {
    vi.resetAllMocks();
    await app.close();
  });

  it('requires no authentication and persists a minimal report', async () => {
    mockCreate.mockResolvedValue(fakeReport());
    app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/abuse-report',
      payload: { domain: 'example.com', reason: 'Too many requests' },
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({ id: 'abuse-1' });
    expect(mockCreate).toHaveBeenCalledWith({
      domain: 'example.com',
      reason: 'Too many requests',
    });
  });

  it('accepts optional details and contact fields', async () => {
    mockCreate.mockResolvedValue(
      fakeReport({ details: 'It hammered our server all night', contact: 'admin@example.com' }),
    );
    app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/abuse-report',
      payload: {
        domain: 'example.com',
        reason: 'Excessive request volume',
        details: 'It hammered our server all night',
        contact: 'admin@example.com',
      },
    });

    expect(response.statusCode).toBe(201);
    expect(mockCreate).toHaveBeenCalledWith({
      domain: 'example.com',
      reason: 'Excessive request volume',
      details: 'It hammered our server all night',
      contact: 'admin@example.com',
    });
  });

  it('rejects a malformed domain with 400, without persisting', async () => {
    app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/abuse-report',
      payload: { domain: 'not a domain', reason: 'Too many requests' },
    });

    expect(response.statusCode).toBe(400);
    expect(mockCreate).not.toHaveBeenCalled();
  });

  it('rejects a missing reason with 400', async () => {
    app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/abuse-report',
      payload: { domain: 'example.com', reason: '' },
    });

    expect(response.statusCode).toBe(400);
    expect(mockCreate).not.toHaveBeenCalled();
  });

  it('returns 429 after exceeding the per-IP hourly submission limit', async () => {
    mockCreate.mockResolvedValue(fakeReport());
    app = await buildTestApp();

    const statusCodes: number[] = [];
    for (let i = 0; i < 11; i++) {
      const response = await app.inject({
        method: 'POST',
        url: '/abuse-report',
        payload: { domain: 'example.com', reason: 'Too many requests' },
      });
      statusCodes.push(response.statusCode);
    }

    expect(statusCodes.slice(0, 10)).toEqual(new Array<number>(10).fill(201));
    expect(statusCodes[10]).toBe(429);
  });
});
