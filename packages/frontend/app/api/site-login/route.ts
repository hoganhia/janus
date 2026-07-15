import { NextResponse } from 'next/server';
import { checkRateLimit } from '@/lib/rate-limit';

const COOKIE_NAME = 'janus_site_auth';
const MAX_ATTEMPTS = 5;
const WINDOW_SECONDS = 15 * 60;

function clientIp(request: Request): string {
  // Vercel sets x-forwarded-for on every request; the first entry is the original client.
  const forwardedFor = request.headers.get('x-forwarded-for');
  return forwardedFor?.split(',')[0]?.trim() ?? 'unknown';
}

export async function POST(request: Request): Promise<NextResponse> {
  const sitePassword = process.env.SITE_PASSWORD;
  if (sitePassword === undefined || sitePassword === '') {
    return NextResponse.json({ error: 'Site password gate is not configured.' }, { status: 500 });
  }

  const { allowed } = await checkRateLimit(
    `site-login-attempts:${clientIp(request)}`,
    MAX_ATTEMPTS,
    WINDOW_SECONDS,
  );
  if (!allowed) {
    return NextResponse.json(
      { error: 'Too many attempts. Try again in a few minutes.' },
      { status: 429 },
    );
  }

  const body = (await request.json()) as { password?: unknown };
  const password = typeof body.password === 'string' ? body.password : '';

  if (password !== sitePassword) {
    return NextResponse.json({ error: 'Incorrect password.' }, { status: 401 });
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(COOKIE_NAME, sitePassword, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 30,
  });
  return response;
}
