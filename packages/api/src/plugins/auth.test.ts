import { getAuth } from '@clerk/fastify';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { requireAuth } from './auth.js';

vi.mock('@clerk/fastify', () => ({ getAuth: vi.fn() }));

const mockGetAuth = vi.mocked(getAuth);

function fakeReply(): {
  reply: FastifyReply;
  status: ReturnType<typeof vi.fn>;
  send: ReturnType<typeof vi.fn>;
} {
  const status = vi.fn().mockReturnThis();
  const send = vi.fn().mockReturnThis();
  return { reply: { status, send } as unknown as FastifyReply, status, send };
}

function fakeRequest(): FastifyRequest {
  return {} as FastifyRequest;
}

describe('requireAuth', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('attaches the verified user ID and does not reply when signed in', async () => {
    mockGetAuth.mockReturnValue({ userId: 'user_123' } as ReturnType<typeof getAuth>);
    const request = fakeRequest();
    const { reply, status } = fakeReply();

    await requireAuth(request, reply);

    expect(request.authUserId).toBe('user_123');
    expect(status).not.toHaveBeenCalled();
  });

  it('replies 401 and leaves authUserId unset when signed out', async () => {
    mockGetAuth.mockReturnValue({ userId: null } as ReturnType<typeof getAuth>);
    const request = fakeRequest();
    const { reply, status, send } = fakeReply();

    await requireAuth(request, reply);

    expect(status).toHaveBeenCalledWith(401);
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ error: 'Unauthorized' }));
    expect(request.authUserId).toBeUndefined();
  });
});
