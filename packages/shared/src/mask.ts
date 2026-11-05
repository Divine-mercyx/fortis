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
  // Paystack/Stripe sk_live_/sk_test_, Stripe restricted rk_ (and pk_ for completeness)
  { re: /\b[spr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g, keepPrefix: (m) => m.indexOf('_', 3) + 1 },
  // Stripe webhook signing secrets
  { re: /\bwhsec_[A-Za-z0-9]{16,}\b/g, keepPrefix: () => 6 },
  // Flutterwave secret keys
  { re: /\bFLWSECK(?:_TEST)?-[A-Za-z0-9]{16,}(?:-X)?\b/g, keepPrefix: (m) => m.indexOf('-') + 1 },
  // Monnify secret/API keys
  { re: /\bMK_(?:PROD|TEST)_[A-Za-z0-9]{8,}\b/g, keepPrefix: () => 8 },
  // AWS access keys, GitHub tokens, Slack tokens
  { re: /\bAKIA[0-9A-Z]{16}\b/g, keepPrefix: () => 4 },
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, keepPrefix: () => 4 },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, keepPrefix: () => 5 },
  // SaaS and registry tokens with fixed prefixes (the long-random rule below misses short or dotted ones)
  { re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, keepPrefix: () => 3 },
  { re: /(?<=hooks\.slack\.com\/(?:services|workflows|triggers)\/T[A-Z0-9]+\/[A-Z0-9]+\/)[A-Za-z0-9]{8,}/g, keepPrefix: () => 0 },
  { re: /(?<=discord(?:app)?\.com\/api\/webhooks\/\d+\/)[A-Za-z0-9_-]{16,}/g, keepPrefix: () => 0 },
  { re: /\b\d{8,10}:AA[A-Za-z0-9_-]{20,}/g, keepPrefix: () => 0 },
  { re: /\bsk-(?:ant-[a-z]+\d{2}|proj|svcacct|admin)-[A-Za-z0-9_-]{16,}/g, keepPrefix: (m) => m.lastIndexOf('-') + 1 },
  { re: /(?<=AccountKey=)[A-Za-z0-9+/]{16,}={0,2}/g, keepPrefix: () => 0 },
  { re: /\b(?:key-[0-9a-f]{16,}|re_[A-Za-z0-9]{6,}_[A-Za-z0-9]{8,}|do[opr]_v1_[a-f0-9]{16,}|rnd_[A-Za-z0-9]{16,}|npm_[A-Za-z0-9]{16,}|pypi-[A-Za-z0-9_-]{16,}|rubygems_[a-f0-9]{16,}|dckr_pat_[A-Za-z0-9_-]{16,})/g, keepPrefix: (m) => Math.max(m.indexOf('_'), m.indexOf('-')) + 1 },
  { re: /(?<=:_authToken=)(?!\$\{)[A-Za-z0-9_.-]{12,}/g, keepPrefix: () => 0 },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}/g, keepPrefix: () => 3 },
  // African payment providers
  { re: /\b(?:SBSECK_|SBTESTSECK_|OPAYPRV|sandbox_sk_)[A-Za-z0-9_]{8,}/g, keepPrefix: (m) => (m.startsWith('OPAYPRV') ? 7 : m.indexOf('_', m.startsWith('sandbox') ? 8 : 0) + 1) },
  // Fortis keys themselves
  { re: /\bfts_[A-Za-z0-9]{20,}\b/g, keepPrefix: () => 4 },
  // Long opaque strings (hex/base64-ish) that look like secrets; URL paths and words are left alone
  { re: /\b[A-Za-z0-9+/_-]{32,}={0,2}/g, keepPrefix: () => 0, when: looksRandom },
  // 11-digit BVN/NIN
  { re: /(?<!\d)\d{11}(?!\d)/g, keepPrefix: () => 0 },
];

/** Passwords inside connection strings: `scheme://user:PASSWORD@host`, `password=…` / `Pwd=…;`. */
const URL_PASSWORD = /(\b[a-z][a-z0-9+.-]*:\/\/[^:/\s@'"`]+:)([^@\s'"`]+)(@)/gi;
const KEY_PASSWORD = /((?:^|[?&;\s])(?:password|pwd)\s*=\s*)([^&;\s'"`]+)/gi;

export function maskSnippet(snippet: string): string {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(snippet)) return '[private key removed]';
  let out = snippet
    .replace(URL_PASSWORD, (m, pre: string, pass: string, at: string) => (pass.includes('••••') ? m : `${pre}${maskValue(pass)}${at}`))
    .replace(KEY_PASSWORD, (m, pre: string, pass: string) => (pass.includes('••••') ? m : `${pre}${maskValue(pass)}`));
  for (const { re, keepPrefix, when } of PATTERNS) {
    out = out.replace(re, (m) => (m.includes('••••') || (when && !when(m)) ? m : maskValue(m, keepPrefix(m))));
  }
  return out.replace(/[\r\n]+/g, ' ').trim();
}

/** Masks multi-line text (tool descriptions and advice) while keeping its line breaks. */
export function maskText(text: string): string {
  return text.split(/\r?\n/).map((l) => (l.trim() ? maskSnippet(l) : '')).join('\n');
}
