// Keys hidden in base64, for "obfuscation" or because a config system wants it.
export const githubToken = Buffer.from('{{GH_TOKEN_B64}}', 'base64').toString(); // @hit
export const githubUrlSafe = '{{GH_TOKEN_B64URL}}'; // @hit
export const signingKey = atob('{{PEM_B64}}'); // @hit
export const databaseUrl = '{{PG_URL_B64}}'; // @hit

// Base64 that isn't a key: text, hashes, images.
export const banner = '{{PLAIN_TEXT_B64}}';
export const integrity = 'sha512-{{SHA512_B64}}';
export const logo = 'data:image/png;base64,{{PNG_B64}}{{PNG_B64}}';
export const user = '{{K8S_USER_B64}}';
