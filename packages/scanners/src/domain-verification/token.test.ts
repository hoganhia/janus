import { describe, expect, it } from 'vitest';
import { generateVerificationToken } from './token.js';

describe('generateVerificationToken', () => {
  it('generates a 48-character lowercase hex string', () => {
    const token = generateVerificationToken();
    expect(token).toMatch(/^[a-f0-9]{48}$/);
  });

  it('generates a different token on every call', () => {
    const tokens = new Set(Array.from({ length: 20 }, () => generateVerificationToken()));
    expect(tokens.size).toBe(20);
  });
});
