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
  // Needs its passphrase too, which usually sits next to it in the same config.
  { re: /-----BEGIN ENCRYPTED PRIVATE KEY-----/g, ruleId: 'SEC-GEN-001', severity: 'high', title: 'Encrypted private key in code' },
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

/** The PEM private-key patterns, as opposed to provider keys that are also called private keys (OPay). */
const isPem = (p: Pattern) => p.re.source.startsWith('-----BEGIN');

/**
 * Whether a PEM header is followed by key material, not a placeholder: in a JSON or YAML string
 * the block is on one line with escaped newlines (`"-----BEGIN PRIVATE KEY-----\nMIIE…"`), in a
 * file it continues on the next line. `…`, `<your key>` and the like are documentation.
 */
function pemHasBody(lines: string[], i: number, after: number): boolean {
  const rest = lines[i]!.slice(after).replace(/\\\\?[nr]/g, '\n');
  // The whole block on this line (a JSON string): judge by this line. Otherwise the key may continue below.
  const body = rest.includes('-----END') ? rest : `${rest}\n${lines[i + 1] ?? ''}\n${lines[i + 2] ?? ''}`;
  return /[A-Za-z0-9+/]{16,}/.test(body.split('-----END')[0]!);
}

function scan(file: SourceFile, patterns: Pattern[]): Detection[] {
  const out: Detection[] = [];
  file.lines.forEach((text, i) => {
    for (const p of patterns) {
      p.re.lastIndex = 0;
      const match = p.re.exec(text);
      // A key prefix followed only by X is a placeholder in docs and fixtures, not a key.
      if (match && !/X{8}/.test(match[0]) && !isIgnored(file, i + 1)) {
        if (isPem(p) && !pemHasBody(file.lines, i, match.index + match[0].length)) continue;
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

/* ---------------------------------------------------------------- notebooks */

const NOTEBOOK = /\.ipynb$/i;
/** Output types that are text. Images and widgets are base64 or JSON blobs, never typed secrets. */
const TEXT_OUTPUTS = ['text/plain', 'text/markdown', 'application/json'];

/**
 * A Jupyter notebook is JSON, so a cell's code sits in escaped strings, sometimes all on one line.
 * This turns it back into the code and text output a person would see, cell by cell, with each line
 * mapped to the notebook line it came from. Null when the file isn't a readable notebook.
 */
export function notebookView(file: SourceFile): { file: SourceFile; lineOf: number[] } | null {
  let nb: { cells?: { source?: unknown; outputs?: { text?: unknown; data?: Record<string, unknown>; traceback?: unknown }[] }[] };
  try {
    nb = JSON.parse(file.text);
  } catch {
    return null;
  }
  if (!nb || !Array.isArray(nb.cells)) return null;
  const lines: string[] = [];
  const lineOf: number[] = [];
  // The notebook line holding a piece of text, JSON-escaped, searching from where the cell starts
  // (Jupyter writes a cell's outputs before its source, so text isn't in reading order).
  let cellStart = 0;
  let cellEnd = 0;
  const locate = (text: string) => {
    const needle = JSON.stringify(text.split('\n')[0]!.slice(0, 120)).slice(1, -1);
    for (let i = cellStart; i < file.lines.length; i++) {
      if (file.lines[i]!.includes(needle)) {
        cellEnd = Math.max(cellEnd, i);
        return i + 1;
      }
    }
    return cellStart + 1;
  };
  const add = (value: unknown) => {
    const chunks = Array.isArray(value) ? value : [value];
    for (const chunk of chunks) {
      if (typeof chunk !== 'string' || !chunk) continue;
      const at = locate(chunk);
      for (const line of chunk.replace(/\n$/, '').split(/\r?\n/)) {
        lines.push(line);
        lineOf.push(at);
      }
    }
  };
  for (const cell of nb.cells) {
    add(cell.source);
    for (const out of cell.outputs ?? []) {
      add(out.text);
      add(out.traceback);
      for (const mime of TEXT_OUTPUTS) add(typeof out.data?.[mime] === 'object' && !Array.isArray(out.data?.[mime]) ? JSON.stringify(out.data[mime]) : out.data?.[mime]);
    }
    // Keep cells apart, so one cell's last line doesn't run into the next one's first.
    lines.push('');
    lineOf.push(lineOf[lineOf.length - 1] ?? 1);
    cellStart = cellEnd;
  }
  return { file: { path: file.path, text: lines.join('\n'), lines }, lineOf };
}

/** Runs a check on what a notebook shows rather than its JSON, and points findings back at the notebook's lines. */
function readable(file: SourceFile, run: (f: SourceFile, raw: boolean) => Detection[]): Detection[] {
  if (!NOTEBOOK.test(file.path)) return run(file, false);
  const view = notebookView(file);
  if (!view) return run(file, true);
  return run(view.file, false).map((d) => ({ ...d, line: view.lineOf[d.line - 1] ?? d.line }));
}

/* ---------------------------------------------------------------- encoded values */

/** A run of base64 (or base64url) long enough to hold a key. Longer than MAX_ENCODED is a file or an image, not a key. */
const BASE64_RUN = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/=_-])/g;
const MAX_ENCODED = 4096;
/** The prefilter for BASE64_RUN, without its lookarounds. */
const LONG_RUN = /[A-Za-z0-9+/_-]{32}/;
/** Base64 values decoded per file at most, so a file of hashes can't slow the scan down. */
const MAX_DECODES = 200;

/** The text a base64 value decodes to, when that's readable text rather than bytes. */
export function decodeBase64(value: string): string | null {
  if (value.length > MAX_ENCODED || value.length % 4 === 1) return null;
  const text = Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  if (text.length < 16) return null;
  let printable = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
  }
  return printable / text.length >= 0.95 ? text : null;
}

/** A named key, a private key or a database password in a piece of text, as a finding title. */
function namedSecret(text: string): { ruleId: string; severity: Detection['severity']; title: string } | null {
  for (const p of [...PAYMENT_KEYS, ...GENERIC]) {
    p.re.lastIndex = 0;
    const m = p.re.exec(text);
    if (!m || /X{8}/.test(m[0])) continue;
    if (isPem(p) && !pemHasBody(text.slice(m.index).split('\n'), 0, m[0].length)) continue;
    return { ruleId: p.ruleId, severity: p.severity, title: p.name ? p.name(m[0]) : p.title };
  }
  const conn = connectionSecret(text);
  return conn ? { ruleId: 'SEC-GEN-001', severity: 'critical', title: conn } : null;
}

const KIND_SECRET = /^kind:\s*["']?Secret["']?\s*(?:#.*)?$/m;
/** Keys in a Kubernetes Secret that hold credentials, as opposed to a username, host or port. */
const SECRET_NAME = /pass|pwd|secret|token|key|cred|auth|cert|private|\.pem$|\.p12$|\.jks$|dsn/i;
const NOT_SECRET_NAME = /^(?:user(?:name)?|login|email|host(?:name)?|port|db|database|namespace|region|tls\.crt|ca\.crt|.*\.crt)$/i;

/**
 * Secrets that are only readable once decoded: base64 values that hold a named key, and the values of
 * a Kubernetes Secret manifest (base64 under `data:`, plain under `stringData:`). Each finding goes to
 * the rule that names that kind of key, FX-SEC-001 for payment keys and SEC-GEN-001 for the rest.
 */
const encodedCache = new WeakMap<SourceFile, Detection[]>();
function encodedSecrets(file: SourceFile): Detection[] {
  const cached = encodedCache.get(file);
  if (cached) return cached;
  const out: Detection[] = [];
  const push = (line: number, found: { ruleId: string; severity: Detection['severity']; title: string }, how: string) => {
    if (isIgnored(file, line) || out.some((d) => d.line === line && d.ruleId === found.ruleId)) return;
    out.push({ ...found, title: `${found.title.replace(/ in code$/, '')} ${how}`, file: file.path, line, snippet: file.lines[line - 1]!.trim() });
  };

  const k8sLines = new Set<number>();
  if (/\.ya?ml$/i.test(file.path) && KIND_SECRET.test(file.text)) {
    for (const [line, name, value, plain] of kubernetesSecretValues(file.lines)) {
      k8sLines.add(line);
      const text = plain ? value : Buffer.from(value, 'base64').toString('utf8');
      const named = namedSecret(text);
      if (named) push(line, named, plain ? 'in a Kubernetes Secret' : 'in a Kubernetes Secret (base64)');
      else if (!NOT_SECRET_NAME.test(name) && SECRET_NAME.test(name) && realValue(text)) {
        push(line, { ruleId: 'SEC-GEN-001', severity: 'high', title: `Kubernetes Secret value for ${name}` }, 'committed to the repository');
      }
    }
  }

  let decodes = 0;
  file.lines.forEach((text, i) => {
    // Cheap tests first: almost no line of code has 32 base64 characters in a row.
    if (decodes >= MAX_DECODES || text.length < 32 || k8sLines.has(i + 1) || !LONG_RUN.test(text)) return;
    for (const m of text.matchAll(BASE64_RUN)) {
      // Base64 of text mixes upper case, lower case and digits; hex hashes and long identifiers don't.
      if (!/[A-Z]/.test(m[0]) || !/[a-z]/.test(m[0]) || !/\d/.test(m[0])) continue;
      if (++decodes > MAX_DECODES) break;
      // An image or font in a data: URL is the one long base64 run that's common and never a key.
      if (/data:[\w/+.-]+;base64,$/.test(text.slice(Math.max(0, m.index! - 40), m.index))) continue;
      const decoded = decodeBase64(m[0]);
      const named = decoded ? namedSecret(decoded) : null;
      if (named) {
        push(i + 1, named, '(base64-encoded)');
        break;
      }
    }
  });
  encodedCache.set(file, out);
  return out;
}

/** A value that is a real credential, not empty, templated or a placeholder. */
function realValue(value: string): boolean {
  const v = value.trim();
  return v.length >= 6 && !PASSWORD_PLACEHOLDER.test(v) && !PLACEHOLDER.test(v) && !/^\{\{.*\}\}$|^\$\{.*\}$/.test(v);
}

/** `[line, key, value, plain]` for each entry under `data:` (base64) or `stringData:` (plain) of each Secret in the file. */
function kubernetesSecretValues(lines: string[]): [number, string, string, boolean][] {
  const out: [number, string, string, boolean][] = [];
  let isSecret = false;
  let entries: [number, string, string, boolean][] = [];
  let block: { indent: number; plain: boolean } | null = null;
  const flush = () => {
    if (isSecret) out.push(...entries);
    isSecret = false;
    entries = [];
    block = null;
  };
  lines.forEach((raw, i) => {
    if (/^---/.test(raw)) return flush();
    if (KIND_SECRET.test(raw)) isSecret = true;
    const indent = raw.length - raw.trimStart().length;
    const text = raw.trim();
    if (!text || text.startsWith('#')) return;
    const head = /^(data|stringData):\s*$/.exec(text);
    if (head) {
      block = { indent, plain: head[1] === 'stringData' };
      return;
    }
    if (block && indent <= block.indent) block = null;
    if (!block) return;
    const m = /^["']?([\w.-]+)["']?\s*:\s*["']?([^"'\s#]*)["']?\s*(?:#.*)?$/.exec(text);
    if (m && m[2]) entries.push([i + 1, m[1]!, m[2], block.plain]);
  });
  flush();
  return out;
}

/** A rule's line findings plus its decoded ones. Where both found a line, the decoded finding says more (which key, where it was hidden). */
function withDecoded(found: Detection[], file: SourceFile, ruleId: string): Detection[] {
  const all = encodedSecrets(file);
  // Whichever rule the decoded finding went to, it replaces a vaguer one on the same line ("Hard-coded PAYSTACK_SECRET_KEY").
  return [...found.filter((d) => !all.some((e) => e.line === d.line)), ...all.filter((d) => d.ruleId === ruleId)];
}

export const paymentKeyRule: FileRule = {
  id: 'FX-SEC-001',
  // In the free secrets pack: genericSecretRule skips payment-key values because this rule
  // reports them, so gating it behind the fintech pack left free users with no detection at all.
  pack: 'secrets',
  appliesTo: ANY_TEXT,
  run: (file) => readable(file, (f) => withDecoded(scan(f, PAYMENT_KEYS), f, 'FX-SEC-001')),
};

/** Test code, including Python's test_*.py and Go's *_test.go. */
const TEST_FILE = /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|fixtures?|mocks?)\/|\.(test|spec|mock|mocks|fixture|stories)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$/i;
/** In tests, a value that spells itself out as fake (`nova_abc12345_secret`, `fake-token-1`) is test data. */
const FAKE_VALUE = /secret|example|dummy|fake|sample|placeholder|changeme|test|mock|abc123|123456|xxxx/i;

export const genericSecretRule: FileRule = {
  id: 'SEC-GEN-001',
  pack: 'secrets',
  appliesTo: ANY_TEXT,
  run: (file) => readable(file, (f, rawJson) => withDecoded(genericLines(f, rawJson), f, 'SEC-GEN-001')),
};

/** The line-by-line checks. `rawJson`: a notebook that isn't valid JSON, read as its text. */
function genericLines(file: SourceFile, rawJson: boolean): Detection[] {
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
  const isNotebook = rawJson;
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
}
