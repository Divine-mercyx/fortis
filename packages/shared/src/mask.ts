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

function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

/** Random-looking: mixes letters and digits, high entropy, and is not a path like /api/v1/wallet/transfer. */
function looksRandom(m: string): boolean {
  if (!/\d/.test(m) || !/[A-Za-z]/.test(m)) return false;
  if ((m.match(/\//g) ?? []).length >= 2 && /^\/?[a-z0-9_-]+(\/[a-z0-9_-]+)+\/?$/i.test(m) && !/\d{4,}/.test(m)) return false;
  return entropy(m) >= 3.8;
}

const PATTERNS: { re: RegExp; keepPrefix: (m: string) => number; when?: (m: string) => boolean }[] = [
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
  // Long opaque strings (hex/base64-ish) that look like secrets; URL paths and words are left alone
  { re: /\b[A-Za-z0-9+/_-]{32,}={0,2}/g, keepPrefix: () => 0, when: looksRandom },
  // 11-digit BVN/NIN
  { re: /(?<!\d)\d{11}(?!\d)/g, keepPrefix: () => 0 },
];

export function maskSnippet(snippet: string): string {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(snippet)) return '[private key removed]';
  let out = snippet;
  for (const { re, keepPrefix, when } of PATTERNS) {
    out = out.replace(re, (m) => (m.includes('••••') || (when && !when(m)) ? m : maskValue(m, keepPrefix(m))));
  }
  return out.replace(/[\r\n]+/g, ' ').trim();
}

/** Masks multi-line text (tool descriptions and advice) while keeping its line breaks. */
export function maskText(text: string): string {
  return text.split(/\r?\n/).map((l) => (l.trim() ? maskSnippet(l) : '')).join('\n');
}
