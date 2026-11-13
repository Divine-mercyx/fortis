import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';

import { env } from '../config/env';

/*
 * Encrypts small secrets the API has to read back, such as authenticator secrets: AES-256-GCM, a
 * random nonce per value, stored as `v1.<nonce>.<tag>.<ciphertext>` in base64url. A database dump
 * alone doesn't give anyone the codes.
 *
 * The key is TWO_FACTOR_KEY when set. Otherwise it's derived from RULES_SIGNING_PRIVATE_KEY, which
 * production already requires, so turning on 2FA needs no new setting. Set TWO_FACTOR_KEY before
 * you ever rotate the rule-signing key, or existing authenticator setups stop working.
 */

let cached: Buffer | null = null;

function key(): Buffer {
  if (cached) return cached;
  if (env.TWO_FACTOR_KEY) cached = createHash('sha256').update(env.TWO_FACTOR_KEY).digest();
  else if (env.RULES_SIGNING_PRIVATE_KEY) cached = Buffer.from(hkdfSync('sha256', env.RULES_SIGNING_PRIVATE_KEY, 'fortis', 'two-factor-secrets', 32));
  else cached = createHash('sha256').update('fortis-development-only-two-factor-key').digest();
  return cached;
}

export function seal(plain: string): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(), nonce);
  const body = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return ['v1', nonce.toString('base64url'), cipher.getAuthTag().toString('base64url'), body.toString('base64url')].join('.');
}

export function open(sealed: string): string {
  const [version, nonce, tag, body] = sealed.split('.');
  if (version !== 'v1' || !nonce || !tag || body === undefined) throw new Error('Unreadable sealed value.');
  const decipher = createDecipheriv('aes-256-gcm', key(), Buffer.from(nonce, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(body, 'base64url')), decipher.final()]).toString('utf8');
}
