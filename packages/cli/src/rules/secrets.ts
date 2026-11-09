import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored } from './types';

const ANY_TEXT = /\.(c|m)?(j|t)sx?$|\.(json|ya?ml|env|toml|ini|properties|py|pyi|ipynb|rb|php|go|java|kt|kts|groovy|scala|swift|dart|rs|vue|svelte|jsp|cshtml|cs|sh|sql|tf|tfvars|txt|md|xml|gradle|cfg|conf|pem|key|plist)$|(^|\/)id_(rsa|ecdsa|ed25519)$|(^|\/)\.env(\.|$)|(^|\/)\.(npmrc|yarnrc|pypirc|netrc)$|(^|\/)Dockerfile$/i;

/** `name` turns the matched key into a more specific title (e.g. which provider it belongs to). */
type Pattern = { re: RegExp; ruleId: string; severity: Detection['severity']; title: string; name?: (key: string) => string; fix?: string };

const PAYMENT_KEYS: Pattern[] = [
  // Paystack, Stripe, Korapay and BudPay share the sk_live_ / sk_test_ prefix; skProvider names it when the shape tells.
  { re: /\bsk_live_[A-Za-z0-9]{20,}\b/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live payment secret key in code', name: (k) => `Live ${skProvider(k)} secret key in code` },
  { re: /\bsk_test_[A-Za-z0-9]{20,}\b/g, ruleId: 'FX-SEC-001', severity: 'high', title: 'Test payment secret key in code', name: (k) => `${skProvider(k)} test secret key in code` },
  { re: /\brk_live_[A-Za-z0-9]{20,}\b/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live Stripe restricted key in code' },
  { re: /\brk_test_[A-Za-z0-9]{20,}\b/g, ruleId: 'FX-SEC-001', severity: 'high', title: 'Stripe test restricted key in code' },
  { re: /\bwhsec_[A-Za-z0-9]{24,}\b/g, ruleId: 'FX-SEC-001', severity: 'high', title: 'Stripe webhook signing secret in code' },
  { re: /\bFLWSECK-[A-Za-z0-9]{20,}-X\b/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live Flutterwave secret key in code' },
  { re: /\bFLWSECK_TEST-[A-Za-z0-9]{20,}-X\b/g, ruleId: 'FX-SEC-001', severity: 'high', title: 'Flutterwave test secret key in code' },
  { re: /\bMK_PROD_[A-Z0-9]{8,}\b/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live Monnify API key in code' },
  // SeerBit: SBSECK_ (live) / SBTESTSECK_ (test) secret keys; SBPUBK_ public keys are meant for the browser.
  // Source: FCMB's SeerBit integration guide, paydocs.fcmb.com/accept-payment/sub-account-integration
  { re: /\bSBSECK_[A-Za-z0-9_]{16,}/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live SeerBit secret key in code' },
  { re: /\bSBTESTSECK_[A-Za-z0-9_]{16,}/g, ruleId: 'FX-SEC-001', severity: 'high', title: 'SeerBit test secret key in code' },
  // OPay: OPAYPRV private key signs requests (HMAC-SHA512); OPAYPUB is the public key.
  // Source: OPay's merchant-cashier-php library (packagist opay/merchant-cashier-php) and documentation.opaycheckout.com/api-signature
  { re: /\bOPAYPRV[A-Za-z0-9]{16,}\b/g, ruleId: 'FX-SEC-001', severity: 'critical', title: 'OPay private key in code' },
  // Squad (GTCO): sandbox secret keys start sandbox_sk_; live keys are a bare sk_ with no documented shape, so only sandbox is named.
  // Source: Squad API docs (squadinc.gitbook.io) and the go-squad SDK, which detects sandbox mode from this prefix
  { re: /\bsandbox_sk_[A-Za-z0-9]{20,}\b/g, ruleId: 'FX-SEC-001', severity: 'high', title: 'Squad sandbox secret key in code' },
];

/**
 * Paystack secret keys are sk_live_/sk_test_ + 40 lowercase hex characters. Stripe's mix upper and
 * lower case and are usually far longer (current keys ~99 characters, starting 51 or 4e). Korapay and
 * BudPay use the same sk_live_ / sk_test_ prefix but document no length or alphabet, so anything else
 * is reported as one of the four rather than guessed.
 *   Korapay: developers.korapay.com (Bearer sk_live_… / sk_test_…; pk_ public keys)
 *   BudPay: BudPay-Org/budpay-woo-commerce-plugin, which accepts only sk_live_/sk_test_ secret and pk_live_/pk_test_ public keys
 */
export const SK_UNKNOWN = 'Stripe, Paystack, Korapay or BudPay';
export function skProvider(key: string): 'Paystack' | 'Stripe' | typeof SK_UNKNOWN {
  const body = key.replace(/^sk_(?:live|test)_/, '');
  if (/^[0-9a-f]{40}$/.test(body)) return 'Paystack';
  if (/[A-Z]/.test(body) && (body.length >= 90 || /^(?:51|4e)/i.test(body))) return 'Stripe';
  return SK_UNKNOWN;
}

const MONO_FIX = 'Move the key to an environment variable or secret manager, then rotate it: in the Mono dashboard (app.mono.co), open the app and regenerate its secret key. A Mono secret key can read the bank data of the customers linked to the app.';
const DOJAH_FIX = 'Move the key to an environment variable or secret manager, then rotate it: in the Dojah dashboard, go to Developers → Configuration and regenerate the secret key for that environment.';
const AT_FIX = "Move the key to an environment variable or secret manager, then rotate it: in the Africa's Talking dashboard, open the app, go to Settings → API Key and generate a new key (the old one stops working).";
const TEST_SK_FIX = 'Move the key to an environment variable or secret manager, then rotate it where it was issued: Mono (app.mono.co → the app → regenerate the secret key) or Dojah (Developers → Configuration → regenerate the sandbox secret key).';

const GENERIC: Pattern[] = [
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, ruleId: 'SEC-GEN-001', severity: 'critical', title: 'Private key in code' },
  { re: /\bAKIA[0-9A-Z]{16}\b/g, ruleId: 'SEC-GEN-001', severity: 'critical', title: 'AWS access key in code' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'GitHub token in code' },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Slack token in code' },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Google API key in code' },
  { re: /\bfts_[A-Za-z0-9]{40}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Fortis CLI key in code' },
  // Open banking and KYC. Public keys (Mono live_pk_/test_pk_, Dojah's widget key) are meant for the browser.
  // Mono: live_sk_ / test_sk_ secret keys, sent as mono-sec-key. Source: Mono's own SDKs (withmono/mono-node,
  // withmono/mono-ruby READMEs: secretKey "live_sk_…" / "test_sk_…"; connect-* SDKs: publicKey "test_pk_…").
  { re: /\blive_sk_[A-Za-z0-9]{16,}\b/g, ruleId: 'SEC-GEN-001', severity: 'critical', title: 'Live Mono secret key in code', fix: MONO_FIX },
  // Dojah: prod_sk_ (production) / test_sk_ (sandbox) secret keys, sent raw in Authorization with an AppId.
  // Source: docs.dojah.io/api-reference/get-started/authentication
  { re: /\bprod_sk_[A-Za-z0-9]{16,}\b/g, ruleId: 'SEC-GEN-001', severity: 'critical', title: 'Live Dojah secret key in code', fix: DOJAH_FIX },
  // Mono and Dojah both use test_sk_ for test keys, and neither documents a length that tells them apart.
  { re: /\btest_sk_[A-Za-z0-9]{16,}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Mono or Dojah test secret key in code', fix: TEST_SK_FIX },
  // Messaging and email
  // Africa's Talking: API keys start atsk_. Source: the key shown in the Africa's Talking dashboard (Settings → API Key),
  // as integration guides quote it; GitGuardian's Africa's Talking detector is also prefix-based. Africa's Talking's own
  // docs don't print a key, so the length isn't pinned down.
  { re: /\batsk_[A-Za-z0-9]{20,}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: "Africa's Talking API key in code", fix: AT_FIX },
  { re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'SendGrid API key in code' },
  { re: /\bkey-[0-9a-f]{32}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Mailgun API key in code' },
  { re: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24,}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Resend API key in code' },
  { re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/T[A-Z0-9]{6,}\/[A-Z0-9]{6,}\/[A-Za-z0-9]{16,}/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Slack webhook URL in code' },
  { re: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{40,}/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Discord webhook URL in code' },
  { re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Telegram bot token in code' },
  // AI providers
  { re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Anthropic API key in code' },
  { re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'OpenAI API key in code' },
  // Cloud and hosting
  { re: /DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/]{40,}={0,2}/g, ruleId: 'SEC-GEN-001', severity: 'critical', title: 'Azure Storage account key in code' },
  { re: /\bdo[opr]_v1_[a-f0-9]{64}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'DigitalOcean token in code' },
  { re: /\brnd_[A-Za-z0-9]{24,}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Render API key in code' },
  // Package registries: a leaked publish token lets anyone release a malicious version of your package
  { re: /\bnpm_[A-Za-z0-9]{36}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'npm access token in code' },
  { re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'PyPI API token in code' },
  { re: /\brubygems_[a-f0-9]{48}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'RubyGems API key in code' },
  { re: /\boy2[a-z0-9]{43}\b/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'NuGet API key in code' },
  { re: /\bdckr_pat_[A-Za-z0-9_-]{27,}/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Docker Hub access token in code' },
  { re: /\/\/[^\s:]+\/:_authToken=(?!\$\{)[A-Za-z0-9_.-]{20,}/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Registry auth token in .npmrc' },
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

/*
 * Connection strings with a password in them. Three shapes:
 *   postgres://user:PASSWORD@host/db   (also mysql, mongodb(+srv), redis(s), amqp(s), mssql, …)
 *   jdbc:sqlserver://host;user=u;password=PASSWORD   or   jdbc:mysql://host/db?user=u&password=PASSWORD
 *   Server=host;User Id=u;Password=PASSWORD;   (.NET / ADO connection strings)
 * Local development databases and placeholders are not reported.
 */
const CONN_URL = /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle|cockroachdb|clickhouse)(?:\+\w+)?):\/\/([^:/\s@'"`]+):([^@\s'"`]+)@([^/\s:'"`?;,)]+)/gi;
const JDBC = /\bjdbc:[a-z0-9]+(?::[a-z0-9]+)?:\/\/([^/\s;:?'"`]+)[^\s'"`]*?[?&;]password=([^&;\s'"`]+)/gi;
const ADO = /(?:^|[;"'\s])(?:server|data source|host|address)\s*=\s*([^;'"`]+);[^'"`]*?\b(?:password|pwd)\s*=\s*([^;'"`]+)/gi;
/** Hosts that only exist on a developer's machine or inside docker-compose. */
const LOCAL_HOST = /^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|db|database|postgres(?:ql)?|mysql|mariadb|mongo(?:db)?|redis|rabbitmq|mssql|sqlserver)$/i;
const PASSWORD_PLACEHOLDER = /^(?:\$\{.*\}|\{.*\}|\$\(.*\)|\$[A-Za-z_]\w*|%\w+%?|<[^>]*>|\{\{.*\}\}|\*+|x+|\.\.\.|password|pass|pwd|secret|changeme|your[_-]?password)$/i;

/** A JWT whose payload grants a privileged role (Supabase's service_role key bypasses row-level security). */
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{20,}/g;
function privilegedJwt(text: string): string | null {
  for (const m of text.matchAll(JWT)) {
    try {
      const payload = JSON.parse(Buffer.from(m[1]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')) as { role?: string; iss?: string };
      if (payload.role === 'service_role') return 'Supabase service_role key in code';
    } catch {
      /* not a JWT we can read */
    }
  }
  return null;
}

/** A Twilio auth token: 32 hex characters assigned to a Twilio setting. (The AC… account SID is an identifier, not a secret.) */
const TWILIO_TOKEN = /\b[\w.-]*twilio[\w.-]*["']?\s*(?:=>|:=|[:=])\s*["'`]?([0-9a-f]{32})\b/i;

function connectionSecret(text: string): string | null {
  const real = (host: string, pass: string) => {
    const h = host.trim().replace(/:\d+$/, '');
    let p = pass.trim();
    try { p = decodeURIComponent(p); } catch { /* keep as written */ }
    return p.length >= 3 && !PASSWORD_PLACEHOLDER.test(p) && !LOCAL_HOST.test(h);
  };
  for (const m of text.matchAll(CONN_URL)) if (real(m[4]!, m[3]!)) return 'Database password in a connection URL';
  for (const m of text.matchAll(JDBC)) if (real(m[1]!, m[2]!)) return 'Database password in a JDBC URL';
  for (const m of text.matchAll(ADO)) if (real(m[1]!, m[2]!)) return 'Database password in a connection string';
  return null;
}

/** `os.getenv("API_KEY", "real-secret")`: read from the environment, but with a real secret to fall back on. */
const ENV_DEFAULT = /\b(?:getenv|environ\.get|config|env(?:\.str)?)\s*\(\s*["']([A-Za-z0-9_.-]*(?:secret|token|api[_-]?key|private[_-]?key|password|passwd)[A-Za-z0-9_.-]*)["']\s*,\s*(?:default\s*=\s*)?["']([^"'\s]{16,})["']/i;
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
/** Routes, URLs without credentials (any scheme; URLs with one are connectionSecret's job), dashed-word labels, variable and setting names (`:login-token="loginToken"`, `"WEBHOOK_SECRET"`) and email addresses are not secrets. */
const NOT_SECRET = /^\/|^[a-z][a-z0-9+.-]*:\/\/(?:[^:@/\s]+@)?[^@\s]+$|^[a-z]+(?:[-_./][a-z]+)+$|^[A-Za-z][a-z]*(?:[A-Z][a-z]+)+$|^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^[^@\s]+@[^@\s]+\.[A-Za-z]+$/;

/** Firebase config files hold client keys that ship inside every app build; they are public by design. */
const FIREBASE_CONFIG = /(^|\/)(google-services\.json|GoogleService-Info\.plist)$/i;

function scan(file: SourceFile, patterns: Pattern[]): Detection[] {
  const out: Detection[] = [];
  file.lines.forEach((text, i) => {
    for (const p of patterns) {
      p.re.lastIndex = 0;
      const match = p.re.exec(text);
      // A key prefix followed only by X is a placeholder in docs and fixtures, not a key.
      if (match && !/X{8}/.test(match[0]) && !isIgnored(file, i + 1)) {
        if (p.title === 'Private key in code' && /"type"\s*:\s*"service_account"/.test(file.text)) {
          out.push({ ruleId: p.ruleId, severity: 'critical', title: 'Google Cloud service account key in code', file: file.path, line: i + 1, snippet: text.trim() });
          continue;
        }
        if (p.title === 'Google API key in code' && FIREBASE_CONFIG.test(file.path)) {
          out.push({ ruleId: p.ruleId, severity: 'low', title: 'Firebase client key (public by design: restrict it to your app in Google Cloud)', file: file.path, line: i + 1, snippet: text.trim() });
          continue;
        }
        p.re.lastIndex = 0;
        const key = p.name ? p.re.exec(text)?.[0] : undefined;
        out.push({ ruleId: p.ruleId, severity: p.severity, title: key ? p.name!(key) : p.title, file: file.path, line: i + 1, snippet: text.trim(), ...(p.fix && { fix: p.fix }) });
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

/** Test code, including Python's test_*.py and Go's *_test.go. */
const TEST_FILE = /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|fixtures?|mocks?)\/|\.(test|spec|mock|mocks|fixture|stories)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$/i;
/** In tests, a value that spells itself out as fake (`nova_abc12345_secret`, `fake-token-1`) is test data. */
const FAKE_VALUE = /secret|example|dummy|fake|sample|placeholder|changeme|test|mock|abc123|123456|xxxx/i;

export const genericSecretRule: FileRule = {
  id: 'SEC-GEN-001',
  pack: 'secrets',
  appliesTo: ANY_TEXT,
  run: (file) => {
    const out = scan(file, GENERIC);
    const inTests = TEST_FILE.test(file.path);
    const looksRandom = (value: string) => !PLACEHOLDER.test(value) && !NOT_SECRET.test(value) && entropy(value) >= 3.5
      && !(inTests && FAKE_VALUE.test(value))
      && !PAYMENT_KEYS.some((p) => { p.re.lastIndex = 0; return p.re.test(value); });
    const reportAs = (title: string, text: string, line: number) => {
      if (isIgnored(file, line) || out.some((d) => d.line === line)) return;
      out.push({ ruleId: 'SEC-GEN-001', severity: 'high', title, file: file.path, line, snippet: text.trim() });
    };
    const report = (name: string, text: string, line: number) => reportAs(`Hard-coded ${name}`, text, line);
    const unquotedAllowed = CONFIG_FILE.test(file.path) && !EXAMPLE_FILE.test(file.path);
    const isNotebook = /\.ipynb$/i.test(file.path);
    file.lines.forEach((raw, i) => {
      // A notebook is JSON, so the quotes in its code cells are escaped.
      const text = isNotebook ? raw.replace(/\\"/g, '"') : raw;
      // Checked before READS_ENV: `process.env.DATABASE_URL || 'postgres://app:pw@db.prod…'` still leaks the fallback.
      const conn = connectionSecret(text);
      if (conn && !isIgnored(file, i + 1) && !out.some((d) => d.line === i + 1)) {
        out.push({ ruleId: 'SEC-GEN-001', severity: 'critical', title: conn, file: file.path, line: i + 1, snippet: raw.trim() });
      }
      const jwt = privilegedJwt(text);
      if (jwt && !isIgnored(file, i + 1) && !out.some((d) => d.line === i + 1)) {
        out.push({ ruleId: 'SEC-GEN-001', severity: 'critical', title: jwt, file: file.path, line: i + 1, snippet: text.trim() });
      }
      if (TWILIO_TOKEN.test(text) && !READS_ENV.test(text) && !isIgnored(file, i + 1) && !out.some((d) => d.line === i + 1)) {
        out.push({ ruleId: 'SEC-GEN-001', severity: 'high', title: 'Twilio auth token in code', file: file.path, line: i + 1, snippet: text.trim() });
      }
      const fallback = ENV_DEFAULT.exec(text);
      if (fallback && looksRandom(fallback[2]!)) report(`default for ${fallback[1]}`, raw, i + 1);
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
