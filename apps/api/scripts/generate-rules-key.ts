// Prints a new Ed25519 key pair for signing rule packs.
// Put the private key in RULES_SIGNING_PRIVATE_KEY (never commit it); ship the public key with the CLI.
import { generateKeyPairSync } from 'node:crypto';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
console.log(privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
console.log(publicKey.export({ type: 'spki', format: 'pem' }).toString());
