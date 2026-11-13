import { describe, expect, it } from 'vitest';

import { base32Decode, base32Encode, newTotpSecret, otpauthUrl, stepAt, totpAt, verifyTotp } from '../src/lib/totp';
import { open, seal } from '../src/lib/secret-box';

// RFC 6238 appendix B: the SHA-1 seed is the ASCII "12345678901234567890". Codes are the last six of its eight digits.
const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
const RFC: [number, string][] = [
  [59, '287082'],
  [1111111109, '081804'],
  [1111111111, '050471'],
  [1234567890, '005924'],
  [2000000000, '279037'],
  [20000000000, '353130'],
];

describe('authenticator codes (RFC 6238)', () => {
  it('matches the RFC 6238 test vectors', () => {
    for (const [seconds, code] of RFC) expect(totpAt(RFC_SECRET, Math.floor(seconds / 30))).toBe(code);
  });

  it('round-trips base32, ignoring case, spaces and padding', () => {
    const bytes = Buffer.from('12345678901234567890', 'ascii');
    expect(base32Encode(bytes)).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(base32Decode('gezd gnbv gy3t qojq gezd gnbv gy3t qojq====')).toEqual(bytes);
    expect(() => base32Decode('not base32!')).toThrow();
    const secret = newTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Decode(secret)).toHaveLength(20);
  });

  it('accepts the current code and one step either side, and nothing further', () => {
    const now = 1_700_000_000_000;
    const step = stepAt(now);
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step), now)).toBe(step);
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step - 1), now)).toBe(step - 1);
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step + 1), now)).toBe(step + 1);
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step - 2), now)).toBeNull();
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step + 2), now)).toBeNull();
  });

  it('refuses a code from a step already used, and anything that is not six digits', () => {
    const now = 1_700_000_000_000;
    const step = stepAt(now);
    const code = totpAt(RFC_SECRET, step);
    expect(verifyTotp(RFC_SECRET, code, now, step)).toBeNull();
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step + 1), now, step)).toBe(step + 1);
    expect(verifyTotp(RFC_SECRET, `${code.slice(0, 3)} ${code.slice(3)}`, now)).toBe(step);
    for (const bad of ['', '12345', '1234567', 'abcdef', '12345a']) expect(verifyTotp(RFC_SECRET, bad, now)).toBeNull();
  });

  it('builds the link authenticator apps read from a QR code', () => {
    const url = new URL(otpauthUrl('JBSWY3DPEHPK3PXP', 'ada@paywave.ng'));
    expect(url.protocol).toBe('otpauth:');
    expect(url.host).toBe('totp');
    expect(decodeURIComponent(url.pathname)).toBe('/Fortis:ada@paywave.ng');
    expect(Object.fromEntries(url.searchParams)).toEqual({ secret: 'JBSWY3DPEHPK3PXP', issuer: 'Fortis', algorithm: 'SHA1', digits: '6', period: '30' });
  });
});

describe('sealed secrets', () => {
  it('encrypts with a fresh nonce each time and reads back', () => {
    const a = seal('JBSWY3DPEHPK3PXP');
    const b = seal('JBSWY3DPEHPK3PXP');
    expect(a).not.toBe(b);
    expect(a).not.toContain('JBSWY3DPEHPK3PXP');
    expect(open(a)).toBe('JBSWY3DPEHPK3PXP');
  });

  it('refuses a value that was tampered with', () => {
    const [v, nonce, tag, body] = seal('JBSWY3DPEHPK3PXP').split('.');
    const flipped = Buffer.from(body!, 'base64url');
    flipped[0] = flipped[0]! ^ 1;
    expect(() => open([v, nonce, tag, flipped.toString('base64url')].join('.'))).toThrow();
    expect(() => open('plain-text-secret')).toThrow();
  });
});
