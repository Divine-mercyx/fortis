import type { Detection, FileRule, SourceFile } from './types';
import { codeOnly, isIgnored, statementAt } from './types';

/*
 * The fintech rules for Go: net/http, Gin, Echo and Fiber handlers, with GORM, sqlx and database/sql.
 * Same rule IDs as the other languages, so they share compliance mapping and the dashboard. Line
 * patterns, conservative like the rest. Silence a reviewed line with `// fortis-ignore`.
 */

export const GO = /\.go$/i;

const MONEY = /transfer|wallet|account|payout|withdraw|deposit|transaction|payment|balance|loan|disburse|beneficiar|card|invoice|ledger|savings|statement/i;
const OWNER = /user_?id|owner|customer_?id|account_?id|tenant|merchant_?id|claims\.|currentUser|session\./i;

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
});

/** The top-level function around a line. gofmt puts `func` and its closing brace at the start of a line. */
function enclosing(file: SourceFile, line: number): { start: number; end: number; text: string } {
  let start = line - 1;
  while (start > 0 && !/^func\b/.test(file.lines[start]!)) start--;
  let end = line - 1;
  while (end < file.lines.length - 1 && !/^}/.test(file.lines[end]!)) end++;
  return { start, end, text: file.lines.slice(start, end + 1).join('\n') };
}

const eachLine = (file: SourceFile, run: (text: string, line: number) => void) =>
  file.lines.forEach((text, i) => {
    if (!isIgnored(file, i + 1)) run(text, i + 1);
  });

/* ---------- FX-OWN-001 ---------- */

const REQUEST_VALUE = /\.Param\(|\.Params\(|\.Query\(|\.QueryParam\(|\.DefaultQuery\(|\.PostForm\(|\.FormValue\(|\.PathValue\(|URLParam\(|mux\.Vars\(|\.URL\.Query\(\)|\bvars\[/;
const HANDLER = /http\.ResponseWriter|\*gin\.Context|echo\.Context|\*fiber\.Ctx/;
const LOOKUP = /\.(?:First|Take|Last|Find|Get|Select|Query|QueryRow|QueryRowx|QueryRowContext|QueryContext|Queryx)\s*\(/;

export const goOwnershipRule: FileRule = {
  id: 'FX-OWN-001',
  pack: 'fintech',
  appliesTo: GO,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (!LOOKUP.test(text)) return;
      const fn = enclosing(file, line);
      if (!HANDLER.test(fn.text) || !MONEY.test(`${file.path}\n${fn.text}`)) return;
      // A record is read by its ID when the query says so, or the ID is First's second argument.
      const nearby = file.lines.slice(Math.max(fn.start, line - 3), Math.min(fn.end + 1, line + 2)).join('\n');
      const byId = /\bwhere\b[^)\n]*?\bid\s*=/i.test(nearby) || /\.(?:First|Take|Last|Find)\s*\(\s*&\w+\s*,\s*[^)]/.test(text);
      if (!byId) return;
      const taken = new Set<string>();
      for (const l of fn.text.split('\n')) {
        const name = /^\s*(\w+)\s*(?:,\s*\w+)?\s*:?=/.exec(l)?.[1];
        if (name && REQUEST_VALUE.test(l)) taken.add(name);
        // Converted on the next line: id, _ := strconv.Atoi(rawID)
        const converted = /^\s*(\w+)\s*(?:,\s*\w+)?\s*:?=\s*(?:strconv\.\w+|uuid\.Parse|uuid\.MustParse)\(\s*(\w+)/.exec(l);
        if (converted && taken.has(converted[2]!)) taken.add(converted[1]!);
      }
      const usesRequest = REQUEST_VALUE.test(nearby) || [...taken].some((name) => new RegExp(`[,(]\\s*${name}\\b`).test(codeOnly(nearby)));
      if (usesRequest && !OWNER.test(nearby)) out.push(hit(file, line, 'FX-OWN-001', 'critical', 'Money record read without an ownership check'));
    });
    return out;
  },
};

/* ---------- FX-HOOK-001 ---------- */

const WEBHOOK_ROUTE = /\.(?:POST|Post|Any|Handle|HandleFunc|Add)\s*\(\s*(?:["`](?:POST|Post)["`]\s*,\s*)?["`][^"`]*webhook[^"`]*["`]/i;
const PROVIDER = /paystack|flutterwave|monnify|interswitch|remita|opay|kora/i;
const VERIFIED = /hmac\.Equal|hmac\.New|subtle\.ConstantTimeCompare|x-paystack-signature|verif-hash|monnify-signature|VerifySignature|ValidateSignature|VerifyWebhook|webhook\w*secret/i;

export const goWebhookRule: FileRule = {
  id: 'FX-HOOK-001',
  pack: 'fintech',
  appliesTo: GO,
  skipTests: true,
  run(file) {
    if (!PROVIDER.test(file.text) || VERIFIED.test(file.text)) return [];
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (WEBHOOK_ROUTE.test(text)) out.push(hit(file, line, 'FX-HOOK-001', 'critical', 'Payment webhook without a signature check'));
    });
    return out;
  },
};

/* ---------- FX-TXN-001 ---------- */

const BALANCE_RMW = /\b[\w.]*Balance\s*[-+]=|\b([\w.]*Balance)\s*=\s*\1\s*[-+]|\b([\w.]*Balance)\s*=\s*\2\.(?:Add|Sub)\s*\(/i;
const PERSISTS = /\.Save\s*\(|\.Update\s*\(|\.Updates\s*\(|\.UpdateColumn\s*\(|\.Exec\s*\(|\.ExecContext\s*\(|\.NamedExec\s*\(/;
const SAFE = /\.Transaction\s*\(|\.Begin\s*\(|\.BeginTx\s*\(|\.Beginx\s*\(|\.MustBegin\s*\(|FOR UPDATE|clause\.Locking|gorm\.Expr\s*\(/;

export const goBalanceRule: FileRule = {
  id: 'FX-TXN-001',
  pack: 'fintech',
  appliesTo: GO,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (!BALANCE_RMW.test(codeOnly(text))) return;
      const fn = enclosing(file, line).text;
      if (PERSISTS.test(fn) && !SAFE.test(fn)) out.push(hit(file, line, 'FX-TXN-001', 'high', 'Balance update outside a transaction'));
    });
    return out;
  },
};

/* ---------- FX-PII-002 and FX-OTP-001 ---------- */

const LOG_CALL = /\b(?:log|logger|logrus|slog|zap|sugar|fmt)\.(?:Print|Println|Printf|Info|Infof|Infow|Warn|Warnf|Warnw|Error|Errorf|Errorw|Debug|Debugf|Debugw|Fatal|Fatalf|Fprintf)\s*\(|\b(?:logger|log|sugar)\.\w+\(\)\.Msg/;
const KYC_VALUE = /\b(?:bvn|nin|bvnNumber|ninNumber|bankVerificationNumber|nationalIdNumber|nationalId)\b/i;
const OTP_VALUE = /\b(?:otp|otpCode|oneTimePassword|passcode|verificationCode)\b/i;
const MASKED = /mask|redact|last4|\[len\(|\*\*\*/i;
/** `len(c.BVN)` and `c.BVN != ""` say whether it's there, not what it is. */
const withoutPresence = (code: string) => code.replace(/\blen\s*\([^)]*\)/g, ' ').replace(/[\w.]+\s*[!=]=\s*(?:nil|\s)/g, ' ');

export const goKycLoggingRule: FileRule = {
  id: 'FX-PII-002',
  pack: 'fintech',
  appliesTo: GO,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (!LOG_CALL.test(text)) return;
      const code = withoutPresence(codeOnly(statementAt(file, line)));
      if (KYC_VALUE.test(code) && !MASKED.test(code)) out.push(hit(file, line, 'FX-PII-002', 'high', 'BVN or NIN written to logs'));
    });
    return out;
  },
};

const WEAK_RANDOM = /\brand\.(?:Intn|Int31n|Int63n|Int|Int31|Int63|Perm|Uint32|Uint64|IntN|N)\s*\(/;
const MATH_RAND = /["`]math\/rand(?:\/v2)?["`]/;
const SECRET_NAME = /\b\w*(?:otp|pin|token|code|passcode|verification)\w*\b/i;
const RESPONSE = /\.JSON\s*\(|\.JSONP\s*\(|\.IndentedJSON\s*\(|Encode\s*\(|\.Status\(\d+\)\.JSON|\.SendString\s*\(|\.String\s*\(/;

export const goOtpRule: FileRule = {
  id: 'FX-OTP-001',
  pack: 'fintech',
  appliesTo: GO,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    const usesMathRand = MATH_RAND.test(file.text);
    eachLine(file, (text, line) => {
      const code = codeOnly(text);
      if (usesMathRand && WEAK_RANDOM.test(code) && SECRET_NAME.test(file.lines.slice(Math.max(0, line - 2), line + 1).join('\n'))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP generated with math/rand'));
        return;
      }
      if (LOG_CALL.test(text)) {
        const stmt = statementAt(file, line);
        const inner = codeOnly(stmt);
        if (OTP_VALUE.test(inner) && !MASKED.test(inner)) out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP written to logs'));
        else if (/\botp\b[^\n]{0,20}?\b\d{4,8}\b/i.test(stmt)) out.push(hit(file, line, 'FX-OTP-001', 'medium', 'Hard-coded OTP in source'));
        return;
      }
      // The name is often a map key, in a string: gin.H{"otp": otp}
      if (RESPONSE.test(code) && /["`]otp["`]\s*:|\bOTP\s*:|\bOtp\s*:/.test(statementAt(file, line))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP returned in an API response'));
      }
    });
    return out;
  },
};

/* ---------- FX-IDEM-001 ---------- */

const MONEY_ROUTE = /\.(?:POST|Post|PUT|Put|Handle|HandleFunc|Add)\s*\(\s*(?:["`](?:POST|PUT)["`]\s*,\s*)?["`](?:(?:POST|PUT)\s+)?[/:][^"`]*(?:transfer|payout|withdraw|disburse|send-money|sendmoney)[^"`]*["`]/i;
/** A path segment that moves money. `payout-processors` is a settings page, and `/payouts/{id}/mark` moves nothing. */
const MOVES_MONEY = /(?:^|\/)(?:transfers?|payouts?|withdraw(?:als?)?|disburse(?:ments?)?|send-?money)(?:\/\{[^}]*\}|\/:[^/]+)*\/?$/i;
const READ_ONLY = /["`][^"`]*\/(?:quote|quotes|fees?|preview|estimate|validate|verify|lookup|name-?enquiry|resolve)["`/?]/i;
const GUARD = /idempot|dedup|replay/i;

export const goIdempotencyRule: FileRule = {
  id: 'FX-IDEM-001',
  pack: 'fintech',
  appliesTo: GO,
  skipTests: true,
  run(file) {
    if (/idempoten/i.test(file.text)) return [];
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (!MONEY_ROUTE.test(text) || READ_ONLY.test(text) || GUARD.test(codeOnly(text))) return;
      const path = /["`](?:(?:POST|PUT)\s+)?([/:][^"`]*)["`]/.exec(text)?.[1] ?? '';
      if (!MOVES_MONEY.test(path)) return;
      // net/http serves every method on a pattern with no method in it, so only those naming one count.
      if (/\.(?:Handle|HandleFunc)\s*\(/.test(text) && !/["`](?:POST|PUT)\s/.test(text)) return;
      out.push(hit(file, line, 'FX-IDEM-001', 'high', 'Transfer without an idempotency key'));
    });
    return out;
  },
};

export const GO_FINTECH_RULES: FileRule[] = [goOwnershipRule, goWebhookRule, goBalanceRule, goKycLoggingRule, goOtpRule, goIdempotencyRule];
