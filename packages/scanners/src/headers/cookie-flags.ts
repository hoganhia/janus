import type { ScanCheckStatus, ScanFinding } from '@janus/shared';

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | undefined;
}

export function parseSetCookieHeader(raw: string): ParsedCookie {
  const [nameValue, ...attrs] = raw.split(';').map((part) => part.trim());
  const name = (nameValue ?? '').split('=')[0]?.trim() ?? '';

  let secure = false;
  let httpOnly = false;
  let sameSite: ParsedCookie['sameSite'];

  for (const attr of attrs) {
    const [rawKey, rawValue] = attr.split('=').map((part) => part.trim());
    const key = (rawKey ?? '').toLowerCase();
    if (key === 'secure') secure = true;
    else if (key === 'httponly') httpOnly = true;
    else if (key === 'samesite') {
      const value = (rawValue ?? '').toLowerCase();
      if (value === 'strict') sameSite = 'Strict';
      else if (value === 'lax') sameSite = 'Lax';
      else if (value === 'none') sameSite = 'None';
    }
  }

  return { name, secure, httpOnly, sameSite };
}

export function evaluateCookie(cookie: ParsedCookie, isHttps: boolean): ScanFinding {
  const issues: string[] = [];
  const fixes: string[] = [];
  let status: ScanCheckStatus = 'pass';

  // SameSite=None without Secure is invalid per spec — browsers reject the cookie outright,
  // so this is worse than a missing-Secure warning: the cookie may simply not work.
  if (cookie.sameSite === 'None' && !cookie.secure) {
    issues.push('sets SameSite=None without Secure, which browsers will reject entirely');
    fixes.push('add the Secure flag (required whenever SameSite=None is used)');
    status = 'fail';
  } else if (isHttps && !cookie.secure) {
    issues.push('is missing the Secure flag, so it could be sent over an unencrypted connection');
    fixes.push('add the Secure flag');
    status = 'fail';
  }

  if (!cookie.httpOnly) {
    issues.push('is missing the HttpOnly flag, so JavaScript on the page can read it');
    fixes.push(
      'add the HttpOnly flag unless client-side JavaScript genuinely needs to read this cookie',
    );
    if (status === 'pass') status = 'warning';
  }
  if (cookie.sameSite === undefined) {
    issues.push('does not set SameSite, relying on the browser default');
    fixes.push(
      'set SameSite explicitly (Lax or Strict, unless the cookie is intentionally used cross-site)',
    );
    if (status === 'pass') status = 'warning';
  }

  const explanation =
    issues.length === 0
      ? `The cookie "${cookie.name}" is set with Secure, HttpOnly, and SameSite=${cookie.sameSite ?? 'default'}.`
      : `The cookie "${cookie.name}" ${issues.join('; and it ')}.`;

  return {
    id: `cookie.${cookie.name}`,
    label: `Cookie: ${cookie.name}`,
    status,
    explanation,
    ...(fixes.length > 0 ? { recommendation: `For this cookie: ${fixes.join('; ')}.` } : {}),
    details: {
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite ?? null,
    },
  };
}

export function evaluateCookies(
  setCookieHeader: string | string[] | undefined,
  isHttps: boolean,
): ScanFinding[] {
  const raw =
    setCookieHeader === undefined
      ? []
      : Array.isArray(setCookieHeader)
        ? setCookieHeader
        : [setCookieHeader];

  if (raw.length === 0) {
    return [
      {
        id: 'cookies.none',
        label: 'Cookies',
        status: 'pass',
        explanation: 'This response did not set any cookies.',
      },
    ];
  }

  return raw.map((header) => evaluateCookie(parseSetCookieHeader(header), isHttps));
}
