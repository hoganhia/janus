import { getAuth } from '@clerk/fastify';
import {
  deleteUserLegalData,
  getCurrentLegalVersion,
  hasAcceptedLatestLegalVersion,
  recordLegalAcceptance,
  type LegalAcceptance,
  type LegalVersion,
} from '@janus/db';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { legalRoutes, legalVersionsRoutes } from './legal.js';

vi.mock('@clerk/fastify', () => ({ getAuth: vi.fn() }));
vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return {
    ...actual,
    getCurrentLegalVersion: vi.fn(),
    recordLegalAcceptance: vi.fn(),
    hasAcceptedLatestLegalVersion: vi.fn(),
    deleteUserLegalData: vi.fn(),
  };
});

const mockGetAuth = vi.mocked(getAuth);
const mockGetCurrentVersion = vi.mocked(getCurrentLegalVersion);
const mockRecordAcceptance = vi.mocked(recordLegalAcceptance);
const mockHasAccepted = vi.mocked(hasAcceptedLatestLegalVersion);
const mockDeleteUserData = vi.mocked(deleteUserLegalData);

const USER_ID = 'user_owner123';

function mockSignedIn(userId: string = USER_ID): void {
  mockGetAuth.mockReturnValue({ userId } as ReturnType<typeof getAuth>);
}
function mockSignedOut(): void {
  mockGetAuth.mockReturnValue({ userId: null } as ReturnType<typeof getAuth>);
}

function fakeVersion(overrides: Partial<LegalVersion> = {}): LegalVersion {
  return {
    id: 'legalver_tos_v1',
    documentType: 'TERMS_OF_SERVICE',
    version: '1.0.0-placeholder',
    changeNote: null,
    effectiveAt: new Date('2026-07-15T00:00:00.000Z'),
    createdAt: new Date('2026-07-15T00:00:00.000Z'),
    ...overrides,
  };
}

function fakeAcceptance(overrides: Partial<LegalAcceptance> = {}): LegalAcceptance {
  return {
    id: 'acceptance-1',
    userId: USER_ID,
    documentType: 'TERMS_OF_SERVICE',
    legalVersionId: 'legalver_tos_v1',
    acceptedAt: new Date('2026-07-15T00:00:00.000Z'),
    ipAddress: '127.0.0.1',
    ...overrides,
  };
}

async function buildTestApp(): Promise<FastifyInstance> {
  const app = Fastify();
  app.setValidatorCompiler(validatorCompiler);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  app.setSerializerCompiler(serializerCompiler);
  await app.register(legalVersionsRoutes);
  await app.register(legalRoutes);
  await app.ready();
  return app;
}

describe('legal routes', () => {
  let app: FastifyInstance;

  beforeEach(() => {
    mockSignedIn();
  });

  afterEach(async () => {
    vi.resetAllMocks();
    await app.close();
  });

  describe('GET /legal/versions', () => {
    it('requires no authentication and returns the current version of every document', async () => {
      mockGetCurrentVersion.mockImplementation((documentType) =>
        Promise.resolve(fakeVersion({ documentType, id: `v-${documentType}` })),
      );
      app = await buildTestApp();

      const response = await app.inject({ method: 'GET', url: '/legal/versions' });

      expect(response.statusCode).toBe(200);
      const body = response.json<Record<string, { version: string; effectiveAt: string }>>();
      expect(body.TERMS_OF_SERVICE?.version).toBe('1.0.0-placeholder');
      expect(body.PRIVACY_POLICY?.version).toBe('1.0.0-placeholder');
      expect(body.ACCEPTABLE_USE_POLICY?.version).toBe('1.0.0-placeholder');
    });
  });

  describe('POST /legal/accept', () => {
    it('rejects an unauthenticated request with 401, without recording anything', async () => {
      mockSignedOut();
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/legal/accept',
        payload: { documentType: 'TERMS_OF_SERVICE' },
      });

      expect(response.statusCode).toBe(401);
      expect(mockRecordAcceptance).not.toHaveBeenCalled();
    });

    it('records acceptance against the current version and returns it', async () => {
      mockRecordAcceptance.mockResolvedValue(fakeAcceptance());
      mockGetCurrentVersion.mockResolvedValue(fakeVersion());
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/legal/accept',
        payload: { documentType: 'TERMS_OF_SERVICE' },
      });

      expect(response.statusCode).toBe(200);
      expect(mockRecordAcceptance).toHaveBeenCalledWith({
        userId: USER_ID,
        documentType: 'TERMS_OF_SERVICE',
        ipAddress: '127.0.0.1',
      });
      const body = response.json<{ documentType: string; version: string }>();
      expect(body.documentType).toBe('TERMS_OF_SERVICE');
      expect(body.version).toBe('1.0.0-placeholder');
    });

    it('rejects an unknown document type with 400', async () => {
      app = await buildTestApp();

      const response = await app.inject({
        method: 'POST',
        url: '/legal/accept',
        payload: { documentType: 'NOT_A_REAL_DOCUMENT' },
      });

      expect(response.statusCode).toBe(400);
      expect(mockRecordAcceptance).not.toHaveBeenCalled();
    });
  });

  describe('GET /legal/status', () => {
    it('rejects an unauthenticated request with 401', async () => {
      mockSignedOut();
      app = await buildTestApp();

      const response = await app.inject({ method: 'GET', url: '/legal/status' });

      expect(response.statusCode).toBe(401);
      expect(mockHasAccepted).not.toHaveBeenCalled();
    });

    it('returns per-document acceptance status for the caller', async () => {
      mockHasAccepted.mockImplementation((_userId, documentType) =>
        Promise.resolve(documentType === 'TERMS_OF_SERVICE'),
      );
      app = await buildTestApp();

      const response = await app.inject({ method: 'GET', url: '/legal/status' });

      expect(response.statusCode).toBe(200);
      const body = response.json<Record<string, boolean>>();
      expect(body.TERMS_OF_SERVICE).toBe(true);
      expect(body.PRIVACY_POLICY).toBe(false);
      expect(body.ACCEPTABLE_USE_POLICY).toBe(false);
      expect(mockHasAccepted).toHaveBeenCalledWith(USER_ID, 'TERMS_OF_SERVICE');
    });
  });

  describe('POST /legal/delete-account', () => {
    it('rejects an unauthenticated request with 401, without deleting anything', async () => {
      mockSignedOut();
      app = await buildTestApp();

      const response = await app.inject({ method: 'POST', url: '/legal/delete-account' });

      expect(response.statusCode).toBe(401);
      expect(mockDeleteUserData).not.toHaveBeenCalled();
    });

    it('deletes the caller’s own consent/acceptance rows and returns the counts', async () => {
      mockDeleteUserData.mockResolvedValue({ scanConsents: 3, legalAcceptances: 2 });
      app = await buildTestApp();

      const response = await app.inject({ method: 'POST', url: '/legal/delete-account' });

      expect(response.statusCode).toBe(200);
      expect(mockDeleteUserData).toHaveBeenCalledWith(USER_ID);
      expect(response.json()).toEqual({ scanConsents: 3, legalAcceptances: 2 });
    });
  });
});
