import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

import { env } from '../config/env';

/**
 * Accepts the Ed25519 private key however a hosting dashboard stored it: a normal PEM,
 * a PEM whose line breaks became spaces or literal "\n", wrapped in quotes, or just the
 * base64 body on one line.
 */
export function parsePrivateKey(raw: string): KeyObject {
  let value = raw.trim().replace(/^["']|["']$/g, '').replace(/\\n/g, '\n');
  const pem = /-----BEGIN ([A-Z ]*PRIVATE KEY)-----([\s\S]*?)-----END \1-----/.exec(value);
  const label = pem?.[1] ?? 'PRIVATE KEY';
  const body = (pem ? pem[2]! : value).replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/=]+$/.test(body)) {
    throw new Error('RULES_SIGNING_PRIVATE_KEY is not a valid key. Paste the PRIVATE KEY block, including the BEGIN and END lines.');
  }
  value = `-----BEGIN ${label}-----\n${body.match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----\n`;
  try {
    const key = createPrivateKey(value);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error(`expected an ed25519 key, got ${key.asymmetricKeyType}`);
    return key;
  } catch (e) {
    throw new Error(
      `RULES_SIGNING_PRIVATE_KEY could not be read (${(e as Error).message}). Paste the PRIVATE KEY block (not the PUBLIC KEY), including the BEGIN and END lines.`,
    );
  }
}

let privateKey: KeyObject;
if (env.RULES_SIGNING_PRIVATE_KEY) {
  privateKey = parsePrivateKey(env.RULES_SIGNING_PRIVATE_KEY);
} else {
  // Development and tests only (production refuses to start without a key).
  privateKey = generateKeyPairSync('ed25519').privateKey;
  if (!env.isTest) console.warn('RULES_SIGNING_PRIVATE_KEY not set: using a temporary signing key.');
}

export const rulesKeyId = env.RULES_SIGNING_KEY_ID;
export const rulesPublicKeyPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();

/** Ed25519 signature over the exact JSON string the CLI receives. */
export function signPayload(payloadJson: string): string {
  return sign(null, Buffer.from(payloadJson), privateKey).toString('base64');
}
