import { NextResponse, type NextRequest } from 'next/server';

const COOKIE_NAME = 'janus_site_auth';

/**
 * Gates the entire site behind a single shared password (SITE_PASSWORD) — a lightweight
 * "give the link + password to a handful of testers" access control, not a real auth system.
 * If SITE_PASSWORD is unset, the gate is a no-op (local dev doesn't require it).
 */
export function middleware(request: NextRequest): NextResponse {
  const sitePassword = process.env.SITE_PASSWORD;
  if (sitePassword === undefined || sitePassword === '') {
    return NextResponse.next();
  }

  const cookie = request.cookies.get(COOKIE_NAME)?.value;
  if (cookie === sitePassword) {
    return NextResponse.next();
  }

  const loginUrl = new URL('/login', request.url);
  loginUrl.searchParams.set('from', request.nextUrl.pathname);
  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: ['/((?!login|api/site-login|_next/static|_next/image|favicon.ico).*)'],
};
