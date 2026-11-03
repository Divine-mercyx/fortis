/**
 * Server-side masking. The CLI masks secrets before upload; the API masks again so a
 * buggy or old client can never store a usable secret or a full BVN/NIN.
 */
const KEEP = 4;

function maskValue(value: string, keepPrefix = 0): string {
  if (value.length <= KEEP + keepPrefix) return '•'.repeat(value.length);
  const prefix = value.slice(0, keepPrefix);
  const tail = value.slice(-KEEP);
  return `${prefix}${'•'.repeat(8)}${tail}`;
}

const PATTERNS: { re: RegExp; keepPrefix: (m: string) => number }[] = [
  // Paystack sk_live_/sk_test_ (and pk_ for completeness)
  { re: /\b[sp]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g, keepPrefix: (m) => m.indexOf('_', 3) + 1 },
  // Flutterwave secret keys
  { re: /\bFLWSECK(?:_TEST)?-[A-Za-z0-9]{16,}(?:-X)?\b/g, keepPrefix: (m) => m.indexOf('-') + 1 },
  // Monnify secret/API keys
  { re: /\bMK_(?:PROD|TEST)_[A-Za-z0-9]{8,}\b/g, keepPrefix: () => 8 },
  // AWS access keys, GitHub tokens, Slack tokens
  { re: /\bAKIA[0-9A-Z]{16}\b/g, keepPrefix: () => 4 },
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, keepPrefix: () => 4 },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, keepPrefix: () => 5 },
  // Fortis keys themselves
  { re: /\bfts_[A-Za-z0-9]{20,}\b/g, keepPrefix: () => 4 },
  // Long opaque strings (hex/base64-ish) that look like secrets
  { re: /\b[A-Za-z0-9+/_-]{32,}={0,2}/g, keepPrefix: () => 0 },
  // 11-digit BVN/NIN
  { re: /(?<!\d)\d{11}(?!\d)/g, keepPrefix: () => 0 },
];

export function maskSnippet(snippet: string): string {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(snippet)) return '[private key removed]';
  let out = snippet;
  for (const { re, keepPrefix } of PATTERNS) {
    out = out.replace(re, (m) => (m.includes('••••') ? m : maskValue(m, keepPrefix(m))));
  }
  return out.replace(/[\r\n]+/g, ' ').trim();
}
