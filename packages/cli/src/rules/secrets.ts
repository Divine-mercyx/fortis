import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored } from './types';

const ANY_TEXT = /\.(c|m)?(j|t)sx?$|\.(json|ya?ml|env|toml|ini|properties|py|rb|php|go|java|kt|cs|sh|tf|txt|md|xml|gradle|pem|key|plist)$|(^|\/)id_(rsa|ecdsa|ed25519)$|(^|\/)\.env(\.|$)|(^|\/)Dockerfile$/i;

type Pattern = { re: RegExp; ruleId: string; severity: Detection['severity']; title: string };

const PAYMENT_KEYS: Pattern[] = [
  { re: /\bsk_live_[A-Za-z0-9]{20,}\b/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live Paystack secret key in code' },
  { re: /\bsk_test_[A-Za-z0-9]{20,}\b/g, ruleId: 'FX-SEC-001', severity: 'high', title: 'Paystack test secret key in code' },
  { re: /\bFLWSECK-[A-Za-z0-9]{20,}-X\b/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live Flutterwave secret key in code' },
  { re: /\bFLWSECK_TEST-[A-Za-z0-9]{20,}-X\b/g, ruleId: 'FX-SEC-001', severity: 'high', title: 'Flutterwave test secret key in code' },
  { re: /\bMK_PROD_[A-Z0-9]{8,}\b/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live Monnify API key in code' },
];

const GENERIC: Pattern[] = [
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, ruleId: 'SEC-GEN-001', severity: 'critical', title: 'Private key in code' },
  { re: /\bAKIA[0-9A-Z]{16}\b/g, ruleId: 'SEC-GEN-001', severity: 'critical', title: 'AWS access key in code' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'GitHub token in code' },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Slack token in code' },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Google API key in code' },
  { re: /\bfts_[A-Za-z0-9]{40}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Fortis CLI key in code' },
];

/** `password = "…"`, `apiKey: '…'` and similar, when the value looks random. */
const ASSIGNMENT = /\b([A-Za-z0-9_]*(?:secret|token|api[_-]?key|private[_-]?key|password|passwd|client[_-]?secret)[A-Za-z0-9_]*)\s*[:=]\s*["'`]([^"'`\s]{16,})["'`]/gi;

function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const PLACEHOLDER = /^(x+|\*+|<.*>|\$\{.*\}|your[_-]|changeme|example|placeholder|dummy|test|sample|redacted)/i;
/** Routes, URLs without credentials and dashed-word labels are not secrets. */
const NOT_SECRET = /^\/|^https?:\/\/[^@\s]+$|^[a-z]+(?:[-_./][a-z]+)+$/;

/** Firebase config files hold client keys that ship inside every app build; they are public by design. */
const FIREBASE_CONFIG = /(^|\/)(google-services\.json|GoogleService-Info\.plist)$/i;

function scan(file: SourceFile, patterns: Pattern[]): Detection[] {
  const out: Detection[] = [];
  file.lines.forEach((text, i) => {
    for (const p of patterns) {
      p.re.lastIndex = 0;
      if (p.re.test(text) && !isIgnored(file, i + 1)) {
        if (p.title === 'Google API key in code' && FIREBASE_CONFIG.test(file.path)) {
          out.push({ ruleId: p.ruleId, severity: 'low', title: 'Firebase client key (public by design: restrict it to your app in Google Cloud)', file: file.path, line: i + 1, snippet: text.trim() });
          continue;
        }
        out.push({ ruleId: p.ruleId, severity: p.severity, title: p.title, file: file.path, line: i + 1, snippet: text.trim() });
      }
    }
  });
  return out;
}

export const paymentKeyRule: FileRule = {
  id: 'FX-SEC-001',
  // In the free secrets pack: genericSecretRule skips payment-key values because this rule
  // reports them, so gating it behind the fintech pack left free users with no detection at all.
  pack: 'secrets',
  appliesTo: ANY_TEXT,
  run: (file) => scan(file, PAYMENT_KEYS),
};

export const genericSecretRule: FileRule = {
  id: 'SEC-GEN-001',
  pack: 'secrets',
  appliesTo: ANY_TEXT,
  run: (file) => {
    const out = scan(file, GENERIC);
    file.lines.forEach((text, i) => {
      if (/process\.env|import\.meta\.env|os\.environ|getenv\(/.test(text)) return;
      ASSIGNMENT.lastIndex = 0;
      for (const m of text.matchAll(ASSIGNMENT)) {
        const value = m[2]!;
        if (PLACEHOLDER.test(value) || NOT_SECRET.test(value) || entropy(value) < 3.5) continue;
        if (PAYMENT_KEYS.some((p) => { p.re.lastIndex = 0; return p.re.test(value); })) continue;
        if (isIgnored(file, i + 1)) continue;
        if (out.some((d) => d.line === i + 1)) continue;
        out.push({ ruleId: 'SEC-GEN-001', severity: 'high', title: `Hard-coded ${m[1]}`, file: file.path, line: i + 1, snippet: text.trim() });
      }
    });
    return out;
  },
};
