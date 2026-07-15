import { describe, expect, it } from 'vitest';
import { evaluateCookie, evaluateCookies, parseSetCookieHeader } from './cookie-flags.js';

describe('parseSetCookieHeader', () => {
  it('parses name, Secure, HttpOnly, and SameSite', () => {
    const cookie = parseSetCookieHeader(
      'session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict',
    );
    expect(cookie).toEqual({ name: 'session', secure: true, httpOnly: true, sameSite: 'Strict' });
  });

  it('defaults flags to false/undefined when absent', () => {
    const cookie = parseSetCookieHeader('tracker=xyz; Path=/; Max-Age=3600');
    expect(cookie).toEqual({
      name: 'tracker',
      secure: false,
      httpOnly: false,
      sameSite: undefined,
    });
  });

  it('is case-insensitive for attribute names and SameSite values', () => {
    const cookie = parseSetCookieHeader('a=b; secure; httponly; samesite=lax');
    expect(cookie).toEqual({ name: 'a', secure: true, httpOnly: true, sameSite: 'Lax' });
  });

  it('handles a cookie with no attributes at all', () => {
    const cookie = parseSetCookieHeader('a=b');
    expect(cookie).toEqual({ name: 'a', secure: false, httpOnly: false, sameSite: undefined });
  });
});

describe('evaluateCookie', () => {
  it('passes a fully-flagged cookie on https', () => {
    const finding = evaluateCookie(
      { name: 's', secure: true, httpOnly: true, sameSite: 'Strict' },
      true,
    );
    expect(finding.status).toBe('pass');
  });

  it('fails a cookie missing Secure on https', () => {
    const finding = evaluateCookie(
      { name: 's', secure: false, httpOnly: true, sameSite: 'Strict' },
      true,
    );
    expect(finding.status).toBe('fail');
  });

  it('does not require Secure on a plain http response', () => {
    const finding = evaluateCookie(
      { name: 's', secure: false, httpOnly: true, sameSite: 'Strict' },
      false,
    );
    expect(finding.status).not.toBe('fail');
  });

  it('fails SameSite=None without Secure regardless of scheme', () => {
    const finding = evaluateCookie(
      { name: 's', secure: false, httpOnly: true, sameSite: 'None' },
      false,
    );
    expect(finding.status).toBe('fail');
    expect(finding.explanation).toContain('SameSite=None');
  });

  it('passes SameSite=None when paired with Secure', () => {
    const finding = evaluateCookie(
      { name: 's', secure: true, httpOnly: true, sameSite: 'None' },
      true,
    );
    expect(finding.status).toBe('pass');
  });

  it('warns (not fails) on missing HttpOnly alone', () => {
    const finding = evaluateCookie(
      { name: 's', secure: true, httpOnly: false, sameSite: 'Strict' },
      true,
    );
    expect(finding.status).toBe('warning');
  });

  it('warns (not fails) on missing SameSite alone', () => {
    const finding = evaluateCookie(
      { name: 's', secure: true, httpOnly: true, sameSite: undefined },
      true,
    );
    expect(finding.status).toBe('warning');
  });

  it('includes the cookie name in the finding id and label', () => {
    const finding = evaluateCookie(
      { name: 'my_cookie', secure: true, httpOnly: true, sameSite: 'Strict' },
      true,
    );
    expect(finding.id).toBe('cookie.my_cookie');
    expect(finding.label).toContain('my_cookie');
  });
});

describe('evaluateCookies', () => {
  it('reports a single pass finding when there are no cookies', () => {
    const findings = evaluateCookies(undefined, true);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.status).toBe('pass');
    expect(findings[0]?.id).toBe('cookies.none');
  });

  it('evaluates a single Set-Cookie header (string, not array)', () => {
    const findings = evaluateCookies('a=b; Secure; HttpOnly; SameSite=Strict', true);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.status).toBe('pass');
  });

  it('evaluates every cookie when Set-Cookie is an array of multiple headers', () => {
    const findings = evaluateCookies(
      ['good=1; Secure; HttpOnly; SameSite=Strict', 'bad=2; SameSite=None'],
      true,
    );
    expect(findings).toHaveLength(2);
    const byId = new Map(findings.map((f) => [f.id, f]));
    expect(byId.get('cookie.good')?.status).toBe('pass');
    expect(byId.get('cookie.bad')?.status).toBe('fail');
  });
});
