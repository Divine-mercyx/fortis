import type { Detection, FileRule, SourceFile } from './types';
import { codeOnly, isIgnored } from './types';

/*
 * The fintech rules for PHP: Laravel controllers, routes and API resources, on Eloquent and the query
 * builder. Same rule IDs as the other languages, so they share compliance mapping and the dashboard.
 * Line patterns, conservative like the rest. Silence a reviewed line with `// fortis-ignore`.
 */

export const PHP = /\.php$/i;
/** Blade templates show data. Language files and config have no request handling. */
const NOT_CODE = /\.blade\.php$|(^|\/)(lang|resources\/lang|config)\//i;

const MONEY = /transfer|wallet|account|payout|withdraw|deposit|transaction|payment|balance|loan|disburse|beneficiar|\bcard\b|invoice|ledger|savings|statement/i;

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
});

const usable = (file: SourceFile) => !NOT_CODE.test(file.path);
const eachLine = (file: SourceFile, run: (text: string, line: number) => void) =>
  file.lines.forEach((text, i) => {
    if (!isIgnored(file, i + 1)) run(text, i + 1);
  });

/**
 * Code with strings blanked out, comments removed, and the variables in "..." kept: "BVN {$user->bvn}"
 * keeps $user->bvn.
 */
export function phpCode(text: string): string {
  const kept = text.replace(/"((?:[^"\\]|\\.)*)"/g, (_, inner: string) => {
    const vars = inner.match(/\$\w+(?:->\w+)*/g);
    return vars ? `" " ${vars.join(' ')}` : '" "';
  });
  // # starts a comment, unless it opens an attribute: #[Route]
  return codeOnly(kept.replace(/(^|\s)#(?!\[).*$/gm, '$1'));
}

/** The statement starting on a line: to its semicolon, or as far as its brackets go. */
function statementAt(file: SourceFile, line: number): string {
  let text = '';
  let depth = 0;
  for (let i = line - 1; i < Math.min(file.lines.length, line + 19); i++) {
    const l = file.lines[i]!;
    text += `${l}\n`;
    for (const ch of phpCode(l)) {
      if ('({['.includes(ch)) depth++;
      else if (')}]'.includes(ch)) depth--;
    }
    if (depth <= 0 && /;\s*(?:\/\/.*)?$/.test(l)) break;
    // A chain often carries on underneath: Route::post(...)\n    ->middleware(...);
    if (depth <= 0 && /[)}\]]\s*$/.test(l) && !(file.lines[i + 1] ?? '').trim().startsWith('->')) break;
  }
  return text;
}

/** The function or closure around a line, from its `function` keyword to its closing brace. */
function enclosing(file: SourceFile, line: number): { start: number; text: string } {
  let start = line - 1;
  while (start > 0 && !/\bfunction\b/.test(phpCode(file.lines[start]!))) start--;
  let depth = 0;
  let opened = false;
  let end = start;
  for (; end < file.lines.length && end < start + 300; end++) {
    for (const ch of phpCode(file.lines[end]!)) {
      if (ch === '{') {
        depth++;
        opened = true;
      } else if (ch === '}') depth--;
    }
    if (opened && depth <= 0 && end >= line - 1) break;
  }
  return { start, text: file.lines.slice(start, end + 1).join('\n') };
}

/* ---------- FX-OWN-001 ---------- */

const FIND_BY_ID = /(?:\w::|->)(?:find|findOrFail|findOr)\s*\(\s*\$(?:\w*[iI]d\b|request->(?:\w*[iI]d\b|input\b|route\b|get\b))|::where\s*\(\s*["'](?:id|uuid)["']\s*,\s*\$/;
const HANDLER_FILE = /Controller\.php$|(^|\/)routes\//;
/** Login screens look up an account before anyone is signed in, and staff can see every customer's records. */
const NOT_CUSTOMER_FACING = /(^|\/)(Auth|Admin|Backend|Backoffice|Nova|Filament)\//;
/** A policy or Gate, or a query limited to the signed-in user. */
const OWNED = /->authorize\s*\(|\bauthorize\s*\(|Gate::|->can\s*\(|->cannot\s*\(|\bpolicy\s*\(|auth\(\)->(?:id|user)|Auth::(?:id|user)|\$request->user\(\)|->user\(\)|user_id|customer_id|owner_id|merchant_id|tenant_id|abort_unless|abort_if/i;

export const phpOwnershipRule: FileRule = {
  id: 'FX-OWN-001',
  pack: 'fintech',
  appliesTo: PHP,
  skipTests: true,
  run(file) {
    if (!usable(file) || !HANDLER_FILE.test(file.path) || NOT_CUSTOMER_FACING.test(file.path)) return [];
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      // The column name is in a string, so this reads the line as written, without its comment.
      if (!FIND_BY_ID.test(text.replace(/\/\/.*$/, ''))) return;
      const fn = enclosing(file, line).text;
      // authorizeResource in the constructor covers every method in the class.
      if (OWNED.test(fn) || /authorizeResource/.test(file.text)) return;
      // The line names what's being read. The file's name may be about something else.
      if (MONEY.test(text)) out.push(hit(file, line, 'FX-OWN-001', 'critical', 'Money record read without an ownership check'));
    });
    return out;
  },
};

/* ---------- FX-HOOK-001 ---------- */

const PROVIDER = /paystack|flutterwave|monnify|interswitch|remita|opay|kora/i;
const VERIFIED = /hash_hmac|hash_equals|x-paystack-signature|verif-hash|monnify-signature|verify\w*signature|validate\w*signature|signature\w*(?:valid|verif)|constructEvent|webhook\w*secret/i;
const CLOSURE_ROUTE = /Route::(?:post|any|match)\s*\([^)]*webhook[^)]*,\s*(?:static\s+)?(?:function|fn)\b/i;
const WEBHOOK_METHOD = /\bfunction\s+(\w*(?:webhook|callback|handle|__invoke)\w*)\s*\(/i;

export const phpWebhookRule: FileRule = {
  id: 'FX-HOOK-001',
  pack: 'fintech',
  appliesTo: PHP,
  skipTests: true,
  run(file) {
    if (!usable(file) || !PROVIDER.test(file.text) || VERIFIED.test(file.text)) return [];
    const isHookController = /Controller\.php$/.test(file.path) && /webhook/i.test(file.path);
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      const code = text;
      if (CLOSURE_ROUTE.test(code)) out.push(hit(file, line, 'FX-HOOK-001', 'critical', 'Payment webhook without a signature check'));
      else if (WEBHOOK_METHOD.test(code) && /Controller\.php$/.test(file.path) && (isHookController || /webhook/i.test(code))) {
        out.push(hit(file, line, 'FX-HOOK-001', 'critical', 'Payment webhook without a signature check'));
      }
    });
    return out;
  },
};

/* ---------- FX-TXN-001 ---------- */

const BALANCE_RMW = /->\w*balance\s*[-+]=|(->\w*balance)\s*=\s*\$\w+\1\s*[-+]|["']\w*balance["']\s*=>\s*\$\w+->\w*balance\s*[-+]/i;
const PERSISTS = /->save\s*\(|->update\s*\(|->saveOrFail\s*\(|->saveQuietly\s*\(|DB::update\s*\(|DB::statement\s*\(/;
const SAFE = /DB::transaction|->transaction\s*\(|lockForUpdate|sharedLock|beginTransaction|DB::raw|FOR UPDATE/i;

export const phpBalanceRule: FileRule = {
  id: 'FX-TXN-001',
  pack: 'fintech',
  appliesTo: PHP,
  skipTests: true,
  run(file) {
    if (!usable(file)) return [];
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      // The array key is in a string, so this reads the line as written.
      if (!BALANCE_RMW.test(text.replace(/\/\/.*$/, ''))) return;
      const fn = enclosing(file, line).text;
      if (PERSISTS.test(fn) && !SAFE.test(fn)) out.push(hit(file, line, 'FX-TXN-001', 'high', 'Balance update outside a transaction'));
    });
    return out;
  },
};

/* ---------- FX-PII-002 and FX-OTP-001 ---------- */

const LOG_CALL = /\bLog::\w+\s*\(|\blogger\s*\(|\bLog::channel\s*\(|\berror_log\s*\(|\binfo\s*\(\s*["'$]/;
const KYC_VALUE = /(?:\$|->)(?:bvn|nin|bvnNumber|ninNumber|bvn_number|nin_number|bankVerificationNumber|nationalIdNumber|nationalId|national_id)\b/i;
const KYC_KEY = /["'](?:bvn|nin|bvn_number|nin_number|national_id)["']\s*=>\s*\$/i;
const OTP_VALUE = /(?:\$|->)(?:otp|otpCode|otp_code|oneTimePassword|passcode|verificationCode|verification_code)\b/i;
const MASKED = /mask|redact|last4|substr\s*\([^)]*-4\s*\)|Str::mask|\*\*\*/i;
/** `isset($c->bvn)`, `empty($c->bvn)` and `strlen($c->bvn)` say whether it's there, not what it is. */
const withoutPresence = (code: string) =>
  code
    .replace(/\b(?:isset|empty|strlen|mb_strlen|is_null|filled|blank)\s*\([^)]*\)/g, ' ')
    .replace(/!!\s*\$[\w>-]+/g, ' ')
    .replace(/\$[\w>-]+\s*(?:!==?|===?)\s*null\b/gi, ' ');

export const phpKycLoggingRule: FileRule = {
  id: 'FX-PII-002',
  pack: 'fintech',
  appliesTo: PHP,
  skipTests: true,
  run(file) {
    if (!usable(file)) return [];
    const isResource = /extends\s+(?:\w+\\)*(?:JsonResource|ResourceCollection)\b/.test(file.text);
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (LOG_CALL.test(text)) {
        const code = withoutPresence(phpCode(statementAt(file, line)));
        if (KYC_VALUE.test(code) && !MASKED.test(code)) out.push(hit(file, line, 'FX-PII-002', 'high', 'BVN or NIN written to logs'));
        return;
      }
      // An API resource sends this to the client: 'bvn' => $this->bvn
      if (isResource && KYC_KEY.test(text) && !MASKED.test(text)) out.push(hit(file, line, 'FX-PII-002', 'high', 'BVN or NIN returned by an API resource'));
    });
    return out;
  },
};

const WEAK_RANDOM = /\b(?:rand|mt_rand|lcg_value|str_shuffle)\s*\(/;
/** uniqid() is often a harmless label, so it only counts for something that's clearly a secret. */
const WEAK_ID = /\buniqid\s*\(/;
const OTP_NAME = /\$\w*(?:otp|passcode|verification)\w*\b/i;
const SECRET_NAME = /\$\w*(?:otp|pin|token|code|passcode|verification)\w*\b|\bfunction\s+\w*(?:otp|pin|token|code|passcode|verification)\w*/i;
const RESPONSE = /\bresponse\(\)->json\s*\(|\bResponse::json\s*\(|\breturn\s*\[|\bnew\s+JsonResponse\s*\(/;

export const phpOtpRule: FileRule = {
  id: 'FX-OTP-001',
  pack: 'fintech',
  appliesTo: PHP,
  skipTests: true,
  run(file) {
    if (!usable(file)) return [];
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      const code = phpCode(text);
      const nearby = file.lines.slice(Math.max(0, line - 3), line).join('\n');
      // A coupon or promo code isn't a secret.
      const isOffer = /\$\w*(?:coupon|promo|voucher|discount|referral|invite)\w*/i.test(nearby);
      if (!isOffer && ((WEAK_RANDOM.test(code) && SECRET_NAME.test(nearby)) || (WEAK_ID.test(code) && OTP_NAME.test(nearby)))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP generated with rand() or mt_rand()'));
        return;
      }
      if (LOG_CALL.test(text)) {
        const stmt = statementAt(file, line);
        const inner = withoutPresence(phpCode(stmt));
        if (OTP_VALUE.test(inner) && !MASKED.test(inner)) out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP written to logs'));
        else if (/\botp\b[^\n]{0,20}?\b\d{4,8}\b/i.test(stmt)) out.push(hit(file, line, 'FX-OTP-001', 'medium', 'Hard-coded OTP in source'));
        return;
      }
      if (RESPONSE.test(code) && /["'](?:otp|otp_code|otpCode)["']\s*=>\s*\$/.test(statementAt(file, line))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP returned in an API response'));
      }
    });
    return out;
  },
};

/* ---------- FX-IDEM-001 ---------- */

const ROUTE = /(?:Route::|\$router->|\$route->)(?:post|put)\s*\(\s*["']([^"']*)["']/i;
/** A path segment that moves money. `payout-processors` is a settings page, and `/payouts/{id}/mark` moves nothing. */
const MOVES_MONEY = /(?:^|\/)(?:transfers?|payouts?|withdraw(?:als?)?|disburse(?:ments?)?|send-?money)(?:\/\{[^}]*\})*\/?$/i;
const READ_ONLY = /\/(?:quote|quotes|fees?|preview|estimate|validate|verify|lookup|name-?enquiry|resolve)\/?$/i;
const GUARD = /idempot|dedup|replay/i;

export const phpIdempotencyRule: FileRule = {
  id: 'FX-IDEM-001',
  pack: 'fintech',
  appliesTo: PHP,
  skipTests: true,
  run(file) {
    if (!usable(file) || /idempoten/i.test(file.text)) return [];
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      const path = ROUTE.exec(text)?.[1];
      if (path === undefined || !MOVES_MONEY.test(path) || READ_ONLY.test(path)) return;
      // Middleware chains on after the route, often on the next lines.
      if (!GUARD.test(statementAt(file, line))) out.push(hit(file, line, 'FX-IDEM-001', 'high', 'Transfer without an idempotency key'));
    });
    return out;
  },
};

export const PHP_FINTECH_RULES: FileRule[] = [phpOwnershipRule, phpWebhookRule, phpBalanceRule, phpKycLoggingRule, phpOtpRule, phpIdempotencyRule];
