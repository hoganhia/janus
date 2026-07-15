import { describe, expect, it } from 'vitest';
import { evaluateSecurityHeaders } from './security-headers.js';

const ALL_GOOD = {
  csp: "default-src 'self'; script-src 'self'",
  hsts: 'max-age=31536000; includeSubDomains',
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: 'geolocation=()',
};

function findBy(id: string, headers: Parameters<typeof evaluateSecurityHeaders>[0]) {
  return evaluateSecurityHeaders(headers).find((f) => f.id === id);
}

describe('evaluateSecurityHeaders', () => {
  it('passes every header when all are well-configured', () => {
    for (const finding of evaluateSecurityHeaders(ALL_GOOD)) {
      expect(finding.status, `${finding.id}: ${finding.explanation}`).toBe('pass');
    }
  });

  describe('CSP', () => {
    it('fails when missing', () => {
      expect(findBy('headers.csp', { ...ALL_GOOD, csp: undefined })?.status).toBe('fail');
    });
    it('fails when script-src allows unsafe-inline', () => {
      expect(
        findBy('headers.csp', { ...ALL_GOOD, csp: "script-src 'self' 'unsafe-inline'" })?.status,
      ).toBe('fail');
    });
    it('fails when script-src allows unsafe-eval', () => {
      expect(
        findBy('headers.csp', { ...ALL_GOOD, csp: "script-src 'self' 'unsafe-eval'" })?.status,
      ).toBe('fail');
    });
    it('fails when script-src is a wildcard', () => {
      expect(findBy('headers.csp', { ...ALL_GOOD, csp: 'script-src *' })?.status).toBe('fail');
    });
    it('fails when there is no script-src or default-src at all', () => {
      expect(findBy('headers.csp', { ...ALL_GOOD, csp: "img-src 'self'" })?.status).toBe('fail');
    });
    it('falls back to default-src when script-src is absent', () => {
      expect(findBy('headers.csp', { ...ALL_GOOD, csp: "default-src 'self'" })?.status).toBe(
        'pass',
      );
    });
  });

  describe('HSTS', () => {
    it('fails when missing', () => {
      expect(findBy('headers.hsts', { ...ALL_GOOD, hsts: undefined })?.status).toBe('fail');
    });
    it('fails when max-age=0 (explicitly disabled)', () => {
      expect(findBy('headers.hsts', { ...ALL_GOOD, hsts: 'max-age=0' })?.status).toBe('fail');
    });
    it('warns when max-age is shorter than the recommended minimum', () => {
      expect(findBy('headers.hsts', { ...ALL_GOOD, hsts: 'max-age=3600' })?.status).toBe('warning');
    });
    it('passes a long max-age', () => {
      expect(findBy('headers.hsts', { ...ALL_GOOD, hsts: 'max-age=31536000' })?.status).toBe(
        'pass',
      );
    });
  });

  describe('X-Frame-Options', () => {
    it('fails when missing', () => {
      expect(
        findBy('headers.x-frame-options', { ...ALL_GOOD, xFrameOptions: undefined })?.status,
      ).toBe('fail');
    });
    it('passes SAMEORIGIN', () => {
      expect(
        findBy('headers.x-frame-options', { ...ALL_GOOD, xFrameOptions: 'SAMEORIGIN' })?.status,
      ).toBe('pass');
    });
    it('warns on an unrecognized value', () => {
      expect(
        findBy('headers.x-frame-options', {
          ...ALL_GOOD,
          xFrameOptions: 'ALLOW-FROM https://x.example',
        })?.status,
      ).toBe('warning');
    });
  });

  describe('X-Content-Type-Options', () => {
    it('fails when missing', () => {
      expect(
        findBy('headers.x-content-type-options', { ...ALL_GOOD, xContentTypeOptions: undefined })
          ?.status,
      ).toBe('fail');
    });
    it('warns on a wrong value', () => {
      expect(
        findBy('headers.x-content-type-options', { ...ALL_GOOD, xContentTypeOptions: 'sniff' })
          ?.status,
      ).toBe('warning');
    });
  });

  describe('Referrer-Policy', () => {
    it('warns (not fails) when missing', () => {
      expect(
        findBy('headers.referrer-policy', { ...ALL_GOOD, referrerPolicy: undefined })?.status,
      ).toBe('warning');
    });
    it('fails unsafe-url specifically', () => {
      expect(
        findBy('headers.referrer-policy', { ...ALL_GOOD, referrerPolicy: 'unsafe-url' })?.status,
      ).toBe('fail');
    });
    it('warns on an unrecognized value', () => {
      expect(
        findBy('headers.referrer-policy', { ...ALL_GOOD, referrerPolicy: 'bogus-value' })?.status,
      ).toBe('warning');
    });
  });

  describe('Permissions-Policy', () => {
    it('warns (not fails) when missing', () => {
      expect(
        findBy('headers.permissions-policy', { ...ALL_GOOD, permissionsPolicy: undefined })?.status,
      ).toBe('warning');
    });
    it('passes when present, regardless of content', () => {
      expect(
        findBy('headers.permissions-policy', { ...ALL_GOOD, permissionsPolicy: 'camera=*' })
          ?.status,
      ).toBe('pass');
    });
  });
});
