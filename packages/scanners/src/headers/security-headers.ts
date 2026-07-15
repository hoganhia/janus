import type { ScanFinding } from '@janus/shared';

type HeaderState = 'present' | 'missing' | 'misconfigured';

const HSTS_RECOMMENDED_MIN_MAX_AGE_SECONDS = 15552000; // ~180 days

function evaluateCsp(value: string | undefined): ScanFinding {
  if (value === undefined) {
    return {
      id: 'headers.csp',
      label: 'Content-Security-Policy',
      status: 'fail',
      explanation:
        'This site does not send a Content-Security-Policy header, so browsers have no extra, built-in defense against script-injection (XSS) attacks.',
      details: { state: 'missing' satisfies HeaderState },
    };
  }

  const directives = value
    .split(';')
    .map((d) => d.trim())
    .filter(Boolean);
  const scriptSrc = directives.find((d) => /^script-src\b/i.test(d));
  const relevant = scriptSrc ?? directives.find((d) => /^default-src\b/i.test(d));

  const issues: string[] = [];
  if (relevant === undefined) {
    issues.push(
      'does not restrict where scripts can be loaded from (no script-src or default-src)',
    );
  } else {
    const lower = relevant.toLowerCase();
    if (lower.includes("'unsafe-inline'")) issues.push("allows 'unsafe-inline' scripts");
    if (lower.includes("'unsafe-eval'")) issues.push("allows 'unsafe-eval'");
    if (/(^|\s)\*(\s|$)/.test(lower)) issues.push('allows scripts from any origin (*)');
  }

  if (issues.length > 0) {
    return {
      id: 'headers.csp',
      label: 'Content-Security-Policy',
      status: 'fail',
      explanation: `This site sends a Content-Security-Policy, but it ${issues.join(' and ')}, which weakens its protection against script-injection attacks.`,
      details: { state: 'misconfigured' satisfies HeaderState, value },
    };
  }

  return {
    id: 'headers.csp',
    label: 'Content-Security-Policy',
    status: 'pass',
    explanation:
      'This site sends a Content-Security-Policy that restricts where scripts can be loaded from.',
    details: { state: 'present' satisfies HeaderState, value },
  };
}

function evaluateHsts(value: string | undefined): ScanFinding {
  if (value === undefined) {
    return {
      id: 'headers.hsts',
      label: 'Strict-Transport-Security',
      status: 'fail',
      explanation:
        'This site does not send a Strict-Transport-Security header, so browsers may still allow insecure HTTP connections to it.',
      details: { state: 'missing' satisfies HeaderState },
    };
  }

  const maxAgeMatch = /max-age=(\d+)/i.exec(value);
  const maxAge = maxAgeMatch?.[1] !== undefined ? Number(maxAgeMatch[1]) : undefined;

  if (maxAge === undefined || Number.isNaN(maxAge)) {
    return {
      id: 'headers.hsts',
      label: 'Strict-Transport-Security',
      status: 'warning',
      explanation:
        'This site sends a Strict-Transport-Security header, but its max-age could not be read.',
      details: { state: 'misconfigured' satisfies HeaderState, value },
    };
  }
  if (maxAge === 0) {
    return {
      id: 'headers.hsts',
      label: 'Strict-Transport-Security',
      status: 'fail',
      explanation:
        'This site sends Strict-Transport-Security with max-age=0, which explicitly turns HSTS off.',
      details: { state: 'misconfigured' satisfies HeaderState, value, maxAge },
    };
  }
  if (maxAge < HSTS_RECOMMENDED_MIN_MAX_AGE_SECONDS) {
    return {
      id: 'headers.hsts',
      label: 'Strict-Transport-Security',
      status: 'warning',
      explanation: `This site sends Strict-Transport-Security, but its max-age (${String(maxAge)} seconds) is shorter than the commonly recommended minimum of about 180 days.`,
      details: { state: 'misconfigured' satisfies HeaderState, value, maxAge },
    };
  }

  return {
    id: 'headers.hsts',
    label: 'Strict-Transport-Security',
    status: 'pass',
    explanation:
      'This site tells browsers to always use HTTPS for it, for a reasonably long duration.',
    details: { state: 'present' satisfies HeaderState, value, maxAge },
  };
}

function evaluateXFrameOptions(value: string | undefined): ScanFinding {
  if (value === undefined) {
    return {
      id: 'headers.x-frame-options',
      label: 'X-Frame-Options',
      status: 'fail',
      explanation:
        'This site does not send an X-Frame-Options header, so it may be possible to embed it in another site’s frame for clickjacking attacks.',
      details: { state: 'missing' satisfies HeaderState },
    };
  }

  const normalized = value.trim().toUpperCase();
  if (normalized === 'DENY' || normalized === 'SAMEORIGIN') {
    return {
      id: 'headers.x-frame-options',
      label: 'X-Frame-Options',
      status: 'pass',
      explanation: `This site sets X-Frame-Options to ${normalized}, preventing it from being embedded in frames on other sites.`,
      details: { state: 'present' satisfies HeaderState, value },
    };
  }

  return {
    id: 'headers.x-frame-options',
    label: 'X-Frame-Options',
    status: 'warning',
    explanation: `This site sends X-Frame-Options with an unrecognized or deprecated value ("${value}"), which not all browsers honor consistently.`,
    details: { state: 'misconfigured' satisfies HeaderState, value },
  };
}

function evaluateXContentTypeOptions(value: string | undefined): ScanFinding {
  if (value === undefined) {
    return {
      id: 'headers.x-content-type-options',
      label: 'X-Content-Type-Options',
      status: 'fail',
      explanation:
        'This site does not send an X-Content-Type-Options header, so some browsers may try to guess ("sniff") a file’s type instead of trusting what the server declared.',
      details: { state: 'missing' satisfies HeaderState },
    };
  }
  if (value.trim().toLowerCase() === 'nosniff') {
    return {
      id: 'headers.x-content-type-options',
      label: 'X-Content-Type-Options',
      status: 'pass',
      explanation:
        'This site sets X-Content-Type-Options: nosniff, preventing browsers from guessing content types.',
      details: { state: 'present' satisfies HeaderState, value },
    };
  }
  return {
    id: 'headers.x-content-type-options',
    label: 'X-Content-Type-Options',
    status: 'warning',
    explanation: `This site sends X-Content-Type-Options with an unexpected value ("${value}") instead of "nosniff".`,
    details: { state: 'misconfigured' satisfies HeaderState, value },
  };
}

const SAFE_REFERRER_POLICIES = new Set([
  'no-referrer',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'origin',
  'origin-when-cross-origin',
  'no-referrer-when-downgrade',
]);

function evaluateReferrerPolicy(value: string | undefined): ScanFinding {
  if (value === undefined) {
    return {
      id: 'headers.referrer-policy',
      label: 'Referrer-Policy',
      status: 'warning',
      explanation:
        'This site does not send a Referrer-Policy header, so it relies on the browser’s default behavior for how much of its URL is shared when visitors click a link away from it.',
      details: { state: 'missing' satisfies HeaderState },
    };
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === 'unsafe-url') {
    return {
      id: 'headers.referrer-policy',
      label: 'Referrer-Policy',
      status: 'fail',
      explanation:
        'This site sets Referrer-Policy to "unsafe-url", which leaks its full URL — including any path or query string — to whatever site a visitor clicks through to next.',
      details: { state: 'misconfigured' satisfies HeaderState, value },
    };
  }
  if (SAFE_REFERRER_POLICIES.has(normalized)) {
    return {
      id: 'headers.referrer-policy',
      label: 'Referrer-Policy',
      status: 'pass',
      explanation: `This site sets Referrer-Policy to "${normalized}", limiting how much URL information is shared with other sites.`,
      details: { state: 'present' satisfies HeaderState, value },
    };
  }
  return {
    id: 'headers.referrer-policy',
    label: 'Referrer-Policy',
    status: 'warning',
    explanation: `This site sends Referrer-Policy with an unrecognized value ("${value}").`,
    details: { state: 'misconfigured' satisfies HeaderState, value },
  };
}

function evaluatePermissionsPolicy(value: string | undefined): ScanFinding {
  if (value === undefined) {
    return {
      id: 'headers.permissions-policy',
      label: 'Permissions-Policy',
      status: 'warning',
      explanation:
        'This site does not send a Permissions-Policy header, so it isn’t explicitly restricting which browser features (camera, microphone, geolocation, etc.) it or embedded content can use.',
      details: { state: 'missing' satisfies HeaderState },
    };
  }
  return {
    id: 'headers.permissions-policy',
    label: 'Permissions-Policy',
    status: 'pass',
    explanation:
      'This site sends a Permissions-Policy header. (This check only confirms the header is present — it does not evaluate whether the specific feature restrictions it sets are appropriate for this site.)',
    details: { state: 'present' satisfies HeaderState, value },
  };
}

export function evaluateSecurityHeaders(headers: {
  csp: string | undefined;
  hsts: string | undefined;
  xFrameOptions: string | undefined;
  xContentTypeOptions: string | undefined;
  referrerPolicy: string | undefined;
  permissionsPolicy: string | undefined;
}): ScanFinding[] {
  return [
    evaluateCsp(headers.csp),
    evaluateHsts(headers.hsts),
    evaluateXFrameOptions(headers.xFrameOptions),
    evaluateXContentTypeOptions(headers.xContentTypeOptions),
    evaluateReferrerPolicy(headers.referrerPolicy),
    evaluatePermissionsPolicy(headers.permissionsPolicy),
  ];
}
