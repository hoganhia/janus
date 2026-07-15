import { NextResponse } from 'next/server';

const COOKIE_NAME = 'janus_site_auth';

export async function POST(request: Request): Promise<NextResponse> {
  const sitePassword = process.env.SITE_PASSWORD;
  if (sitePassword === undefined || sitePassword === '') {
    return NextResponse.json({ error: 'Site password gate is not configured.' }, { status: 500 });
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
