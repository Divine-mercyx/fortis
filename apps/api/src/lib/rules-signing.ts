import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

import { env } from '../config/env';

let privateKey: KeyObject;
if (env.RULES_SIGNING_PRIVATE_KEY) {
  privateKey = createPrivateKey(env.RULES_SIGNING_PRIVATE_KEY.replace(/\\n/g, '\n'));
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
