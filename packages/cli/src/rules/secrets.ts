import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored } from './types';

const ANY_TEXT = /\.(c|m)?(j|t)sx?$|\.(json|ya?ml|env|toml|ini|properties|py|rb|php|go|java|kt|kts|groovy|scala|swift|dart|rs|vue|svelte|jsp|cshtml|cs|sh|sql|tf|tfvars|txt|md|xml|gradle|cfg|conf|pem|key|plist)$|(^|\/)id_(rsa|ecdsa|ed25519)$|(^|\/)\.env(\.|$)|(^|\/)Dockerfile$/i;

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

/** `password = "…"`, `apiKey: '…'`, PHP's `'api_key' => '…'`, Go's `token := "…"` and similar, when the value looks random. */
const ASSIGNMENT = /\b([A-Za-z0-9_]*(?:secret|token|api[_-]?key|private[_-]?key|password|passwd|client[_-]?secret)[A-Za-z0-9_]*)["']?\s*(?:=>|:=|[:=])\s*["'`]([^"'`\s]{16,})["'`]/gi;

/** Config files where values go unquoted: `spring.datasource.password=…`, `API_TOKEN: …`. */
const CONFIG_FILE = /\.(env|properties|ya?ml|ini|toml|conf|cfg)$|(^|\/)\.env(\.|$)/i;
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
const CONN_URL = /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|cockroachdb|clickhouse)):\/\/([^:/\s@'"`]+):([^@\s'"`]+)@([^/\s:'"`?;,)]+)/gi;
const JDBC = /\bjdbc:[a-z0-9]+(?::[a-z0-9]+)?:\/\/([^/\s;:?'"`]+)[^\s'"`]*?[?&;]password=([^&;\s'"`]+)/gi;
const ADO = /(?:^|[;"'\s])(?:server|data source|host|address)\s*=\s*([^;'"`]+);[^'"`]*?\b(?:password|pwd)\s*=\s*([^;'"`]+)/gi;
/** Hosts that only exist on a developer's machine or inside docker-compose. */
const LOCAL_HOST = /^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|db|database|postgres(?:ql)?|mysql|mariadb|mongo(?:db)?|redis|rabbitmq|mssql|sqlserver)$/i;
const PASSWORD_PLACEHOLDER = /^(?:\$\{.*\}|\$\(.*\)|\$[A-Za-z_]\w*|%\w+%?|<[^>]*>|\{\{.*\}\}|\*+|x+|\.\.\.|password|pass|pwd|secret|changeme|your[_-]?password)$/i;

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
/** Routes, URLs without credentials (any scheme; URLs with one are connectionSecret's job), dashed-word labels and variable names (`:login-token="loginToken"`) are not secrets. */
const NOT_SECRET = /^\/|^[a-z][a-z0-9+.-]*:\/\/(?:[^:@/\s]+@)?[^@\s]+$|^[a-z]+(?:[-_./][a-z]+)+$|^[A-Za-z][a-z]*(?:[A-Z][a-z]+)+$/;

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
    const report = (name: string, text: string, line: number) => {
      if (isIgnored(file, line) || out.some((d) => d.line === line)) return;
      out.push({ ruleId: 'SEC-GEN-001', severity: 'high', title: `Hard-coded ${name}`, file: file.path, line, snippet: text.trim() });
    };
    const unquotedAllowed = CONFIG_FILE.test(file.path) && !EXAMPLE_FILE.test(file.path);
    file.lines.forEach((text, i) => {
      // Checked before READS_ENV: `process.env.DATABASE_URL || 'postgres://app:pw@db.prod…'` still leaks the fallback.
      const conn = connectionSecret(text);
      if (conn && !isIgnored(file, i + 1) && !out.some((d) => d.line === i + 1)) {
        out.push({ ruleId: 'SEC-GEN-001', severity: 'critical', title: conn, file: file.path, line: i + 1, snippet: text.trim() });
      }
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
