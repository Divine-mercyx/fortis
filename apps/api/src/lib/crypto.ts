import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** Random base62 string with ~6 bits per character from a CSPRNG (rejection sampling, no bias). */
export function randomBase62(length: number): string {
  let out = '';
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      if (byte < 248) out += BASE62[byte % 62];
      if (out.length === length) break;
    }
  }
  return out;
}

export const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** CLI keys look like fts_<40 base62 chars>. Only the SHA-256 is stored. */
export const TOKEN_PREFIX = 'fts_';
export function newProjectToken() {
  const token = `${TOKEN_PREFIX}${randomBase62(40)}`;
  return { token, hash: sha256(token), displayPrefix: token.slice(0, 12) };
}

export function newSessionToken() {
  const token = randomBytes(32).toString('base64url');
  return { token, hash: sha256(token) };
}
