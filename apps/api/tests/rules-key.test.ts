import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { parsePrivateKey } from '../src/lib/rules-signing';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const body = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');

describe('parsePrivateKey', () => {
  it.each([
    ['a normal PEM', pem],
    ['line breaks turned into spaces', pem.replace(/\n/g, ' ')],
    ['line breaks removed', pem.replace(/\n/g, '')],
    ['literal \\n escapes', pem.replace(/\n/g, '\\n')],
    ['wrapped in quotes', `"${pem}"`],
    ['just the base64 body', body],
  ])('reads %s', (_label, value) => {
    expect(parsePrivateKey(value).asymmetricKeyType).toBe('ed25519');
  });

  it('explains when the public key is pasted by mistake', () => {
    const pub = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect(() => parsePrivateKey(pub)).toThrow(/PRIVATE KEY block/);
  });

  it('explains when the value is not a key at all', () => {
    expect(() => parsePrivateKey('not a key!')).toThrow(/not a valid key/);
  });
});
