import { describe, expect, it } from 'vitest';
import { buildVerificationInstructions, verificationTxtRecordName } from './constants.js';

describe('verificationTxtRecordName', () => {
  it('prefixes the domain with _janus-verify', () => {
    expect(verificationTxtRecordName('example.com')).toBe('_janus-verify.example.com');
  });
});

describe('buildVerificationInstructions', () => {
  it('builds DNS TXT instructions', () => {
    const instructions = buildVerificationInstructions('example.com', 'DNS_TXT', 'abc123');
    expect(instructions).toEqual({
      method: 'DNS_TXT',
      recordName: '_janus-verify.example.com',
      recordType: 'TXT',
      recordValue: 'abc123',
    });
  });

  it('builds well-known file instructions', () => {
    const instructions = buildVerificationInstructions('example.com', 'WELL_KNOWN_FILE', 'abc123');
    expect(instructions).toEqual({
      method: 'WELL_KNOWN_FILE',
      url: 'https://example.com/.well-known/janus-verify.txt',
      fileContent: 'abc123',
    });
  });
});
