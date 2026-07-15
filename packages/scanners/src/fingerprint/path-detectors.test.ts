import { describe, expect, it } from 'vitest';
import { evaluatePathCheck, PATH_CHECKS } from './path-detectors.js';

const wpLogin = PATH_CHECKS.find((c) => c.path === '/wp-login.php');
const wpReadme = PATH_CHECKS.find((c) => c.path === '/readme.html');
const nextStatic = PATH_CHECKS.find((c) => c.path === '/_next/static/');

describe('evaluatePathCheck', () => {
  it('confirms presence via a matching status code with no version', () => {
    if (!wpLogin) throw new Error('expected /wp-login.php check to exist');
    const result = evaluatePathCheck(wpLogin, 200, undefined);
    expect(result).toEqual({
      productKey: 'wordpress',
      version: undefined,
      path: '/wp-login.php',
      label: wpLogin.label,
    });
  });

  it('treats a 403 as presence too (path exists but isn’t listable)', () => {
    if (!wpLogin) throw new Error('expected /wp-login.php check to exist');
    expect(evaluatePathCheck(wpLogin, 403, undefined)?.productKey).toBe('wordpress');
  });

  it('returns undefined when the status code indicates absence', () => {
    if (!wpLogin) throw new Error('expected /wp-login.php check to exist');
    expect(evaluatePathCheck(wpLogin, 404, undefined)).toBeUndefined();
  });

  it('extracts a version from the WordPress readme body', () => {
    if (!wpReadme) throw new Error('expected /readme.html check to exist');
    const body = Buffer.from('<h1>WordPress</h1>\n<h2>Version 6.4.2</h2>\n');
    const result = evaluatePathCheck(wpReadme, 200, body);
    expect(result?.version).toBe('6.4.2');
  });

  it('has no version when the body was not captured', () => {
    if (!wpReadme) throw new Error('expected /readme.html check to exist');
    const result = evaluatePathCheck(wpReadme, 200, undefined);
    expect(result?.version).toBeUndefined();
  });

  it('has no version when the body does not contain a recognizable version string', () => {
    if (!wpReadme) throw new Error('expected /readme.html check to exist');
    const result = evaluatePathCheck(wpReadme, 200, Buffer.from('<html>nothing here</html>'));
    expect(result?.version).toBeUndefined();
  });

  it('detects Next.js presence via its static asset directory', () => {
    if (!nextStatic) throw new Error('expected /_next/static/ check to exist');
    expect(evaluatePathCheck(nextStatic, 200, undefined)?.productKey).toBe('nextjs');
  });
});
