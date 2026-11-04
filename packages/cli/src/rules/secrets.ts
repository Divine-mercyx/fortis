import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored, TEST_PATH } from './types';

const ANY_TEXT = /\.(c|m)?(j|t)sx?$|\.(json|ya?ml|env|toml|ini|properties|py|pyi|ipynb|rb|php|go|java|kt|kts|groovy|scala|swift|dart|rs|vue|svelte|jsp|cshtml|cs|sh|sql|tf|tfvars|txt|md|xml|gradle|cfg|conf|pem|key|plist)$|(^|\/)id_(rsa|ecdsa|ed25519)$|(^|\/)\.env(\.|$)|(^|\/)Dockerfile$|(^|\/)\.pypirc$|(^|\/)pip\.conf$/i;

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
  { re: /\bpypi-[A-Za-z0-9_-]{50,}/g, ruleId: 'SEC-GEN-001', severity: 'critical', title: 'PyPI token in code' },
];

/** `password = "…"`, `apiKey: '…'`, PHP's `'api_key' => '…'`, Go's `token := "…"` and similar, when the value looks random. */
const ASSIGNMENT = /\b([A-Za-z0-9_]*(?:secret|token|api[_-]?key|private[_-]?key|password|passwd|client[_-]?secret)[A-Za-z0-9_]*)["']?\s*(?:=>|:=|[:=])\s*["'`]([^"'`\s]{16,})["'`]/gi;

/** Config files where values go unquoted: `spring.datasource.password=…`, `API_TOKEN: …`. */
const CONFIG_FILE = /\.(env|properties|ya?ml|ini|toml|conf|cfg)$|(^|\/)\.env(\.|$)|(^|\/)\.pypirc$/i;
const EXAMPLE_FILE = /\.(example|sample|template|dist|tmpl)$|\.(example|sample)\./i;
const UNQUOTED = /^\s*(?:export\s+|-\s+)?([A-Za-z0-9_.-]*(?:secret|token|api[_-]?key|private[_-]?key|password|passwd)[A-Za-z0-9_.-]*)\s*[:=]\s*([^\s"'`#]{16,})\s*(?:#.*)?$/i;
/** Key files, keystores and dotted class names are settings that point at a secret, not the secret. */
const CONFIG_REFERENCE = /^(?:classpath|file|env|vault|secretref|arn):|^\.{0,2}\/|^[\w./-]+\.(?:pem|key|jks|p12|pfx|json|ya?ml|crt)$|^(?:[A-Za-z_][\w$]*\.){2,}[\w$]+$/;

/** The value on this line comes from the environment, in any of the languages we scan. */
const READS_ENV = /process\.env|import\.meta\.env|os\.environ|getenv\(|\benv\(|\$_ENV|\$_SERVER|System\.getProperty|GetEnvironmentVariable|\bENV\[|@Value\(/;

/** `os.getenv("API_KEY", "real-secret")`: read from the environment, but with a real secret to fall back on. */
const ENV_DEFAULT = /\b(?:getenv|environ\.get|config|env(?:\.str)?)\s*\(\s*["']([A-Za-z0-9_.-]*(?:secret|token|api[_-]?key|private[_-]?key|password|passwd)[A-Za-z0-9_.-]*)["']\s*,\s*(?:default\s*=\s*)?["']([^"'\s]{16,})["']/i;
/** `postgresql://app:password@db.internal/wallet`, including broker URLs and SQLAlchemy's `+driver` form. */
const CONNECTION_URL = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|oracle)(?:\+\w+)?:\/\/[^\s:@/'"`]*:([^\s@/'"`]+)@([^\s:/'"`]+)/i;
const DEFAULT_PASSWORD = /^(password|pass|pwd|secret|postgres|root|admin|guest|user|\*+)$|[${<%]/i;
/** Hosts that only exist on a developer's machine or in a local docker-compose. */
const LOCAL_HOST = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|db|database|postgres|mysql|mariadb|redis|rabbitmq|mongo|mongodb|host|example\.com)$/i;
/** `git+https://ghp_abc@github.com/...`: a token used as the URL's username or password. */
const URL_TOKEN = /\bhttps?:\/\/(?:[\w.-]+:)?([A-Za-z0-9_-]{20,})@[\w.-]+/;

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

const PLACEHOLDER = /^(x+|\*+|<.*>|\$\{.*\}|\$[A-Za-z_]|%[\w(]|\{\{|\{cipher\}|ENC\(|your[_-]|changeme|example|placeholder|dummy|test|sample|redacted)/i;
/** Routes, URLs without credentials, dashed-word labels, variable and setting names (`:login-token="loginToken"`, `"WEBHOOK_SECRET"`) and email addresses are not secrets. */
const NOT_SECRET = /^\/|^https?:\/\/[^@\s]+$|^[a-z]+(?:[-_./][a-z]+)+$|^[A-Za-z][a-z]*(?:[A-Z][a-z]+)+$|^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^[^@\s]+@[^@\s]+\.[A-Za-z]+$/;

/** Firebase config files hold client keys that ship inside every app build; they are public by design. */
const FIREBASE_CONFIG = /(^|\/)(google-services\.json|GoogleService-Info\.plist)$/i;

function scan(file: SourceFile, patterns: Pattern[]): Detection[] {
  const out: Detection[] = [];
  file.lines.forEach((text, i) => {
    for (const p of patterns) {
      p.re.lastIndex = 0;
      const match = p.re.exec(text);
      // `sk_live_XXXXXXXXXXXX` is a placeholder in docs and fixtures, not a key.
      if (match && !/X{8}/.test(match[0]) && !isIgnored(file, i + 1)) {
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
    const looksRandom = (value: string) => !PLACEHOLDER.test(value) && !NOT_SECRET.test(value) && entropy(value) >= 3.5
      && !PAYMENT_KEYS.some((p) => { p.re.lastIndex = 0; return p.re.test(value); });
    const reportAs = (title: string, text: string, line: number) => {
      if (isIgnored(file, line) || out.some((d) => d.line === line)) return;
      out.push({ ruleId: 'SEC-GEN-001', severity: 'high', title, file: file.path, line, snippet: text.trim() });
    };
    const report = (name: string, text: string, line: number) => reportAs(`Hard-coded ${name}`, text, line);
    // Test fixtures are full of fake passwords. Real key shapes above still count there; guesses from a name don't.
    if (TEST_PATH.test(file.path)) return out;
    const unquotedAllowed = CONFIG_FILE.test(file.path) && !EXAMPLE_FILE.test(file.path);
    const isNotebook = /\.ipynb$/i.test(file.path);
    file.lines.forEach((raw, i) => {
      // A notebook is JSON, so the quotes in its code cells are escaped.
      const text = isNotebook ? raw.replace(/\\"/g, '"') : raw;
      const fallback = ENV_DEFAULT.exec(text);
      if (fallback && looksRandom(fallback[2]!)) report(`default for ${fallback[1]}`, raw, i + 1);
      const url = CONNECTION_URL.exec(text);
      if (url && !DEFAULT_PASSWORD.test(url[1]!) && !LOCAL_HOST.test(url[2]!)) reportAs('Password in a connection URL', raw, i + 1);
      const token = URL_TOKEN.exec(text);
      if (token && /\d/.test(token[1]!) && looksRandom(token[1]!)) reportAs('Credential in a URL', raw, i + 1);
      if (READS_ENV.test(text)) return;
      ASSIGNMENT.lastIndex = 0;
      for (const m of text.matchAll(ASSIGNMENT)) {
        if (looksRandom(m[2]!)) report(m[1]!, text, i + 1);
      }
      if (!unquotedAllowed) return;
      const m = UNQUOTED.exec(text);
      // Requiring a digit keeps out plain settings such as `token-header: X-Auth-Token-Name`.
      if (m && /\d/.test(m[2]!) && !CONFIG_REFERENCE.test(m[2]!) && looksRandom(m[2]!)) report(m[1]!, text, i + 1);
    });
    return out;
  },
};
