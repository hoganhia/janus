import { describe, expect, it } from 'vitest';
import { detectFromHeaders } from './header-detectors.js';

describe('detectFromHeaders', () => {
  it('extracts product and version from a Server header', () => {
    const detections = detectFromHeaders({
      server: 'nginx/1.18.0 (Ubuntu)',
      xPoweredBy: undefined,
    });
    expect(detections).toEqual([
      {
        productKey: 'nginx',
        version: '1.18.0',
        source: 'Server',
        rawValue: 'nginx/1.18.0 (Ubuntu)',
      },
    ]);
  });

  it('extracts product and version from an X-Powered-By header', () => {
    const detections = detectFromHeaders({ server: undefined, xPoweredBy: 'PHP/8.1.2' });
    expect(detections).toEqual([
      { productKey: 'php', version: '8.1.2', source: 'X-Powered-By', rawValue: 'PHP/8.1.2' },
    ]);
  });

  it('detects a product with no version present in the header', () => {
    const detections = detectFromHeaders({ server: undefined, xPoweredBy: 'Express' });
    expect(detections).toEqual([
      { productKey: 'express', version: undefined, source: 'X-Powered-By', rawValue: 'Express' },
    ]);
  });

  it('is case-insensitive', () => {
    const detections = detectFromHeaders({ server: 'MICROSOFT-IIS/10.0', xPoweredBy: undefined });
    expect(detections[0]?.productKey).toBe('iis');
    expect(detections[0]?.version).toBe('10.0');
  });

  it('returns nothing for headers not in the catalog (e.g. a CDN)', () => {
    const detections = detectFromHeaders({ server: 'cloudflare', xPoweredBy: undefined });
    expect(detections).toEqual([]);
  });

  it('returns nothing when both headers are absent', () => {
    expect(detectFromHeaders({ server: undefined, xPoweredBy: undefined })).toEqual([]);
  });

  it('detects both headers independently when both are present', () => {
    const detections = detectFromHeaders({ server: 'nginx/1.20.0', xPoweredBy: 'PHP/7.4.3' });
    expect(detections).toHaveLength(2);
    expect(detections.map((d) => d.productKey).sort()).toEqual(['nginx', 'php']);
  });
});
