import type { Detection, FileRule, SourceFile } from './types';
import { codeOnly, isIgnored } from './types';

/*
 * The fintech rules for Java and Kotlin: Spring Boot controllers and services, on Spring Data and
 * JdbcTemplate. Same rule IDs as the other languages, so they share compliance mapping and the
 * dashboard. Line patterns, conservative like the rest. Silence a reviewed line with `// fortis-ignore`.
 */

export const JVM = /\.(java|kt)$/i;

const MONEY = /transfer|wallet|account|payout|withdraw|deposit|transaction|payment|balance|loan|disburse|beneficiar|\bcard|invoice|ledger|savings|statement/i;

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
});

const eachLine = (file: SourceFile, run: (text: string, line: number) => void) =>
  file.lines.forEach((text, i) => {
    if (!isIgnored(file, i + 1)) run(text, i + 1);
  });

/** Code with strings blanked out, but Kotlin's "$bvn" and "${user.bvn}" kept. */
export function jvmCode(text: string): string {
  const kept = text.replace(/"((?:[^"\\]|\\.)*)"/g, (_, inner: string) => {
    const values = [...inner.matchAll(/\$\{([^}]+)\}|\$([A-Za-z_]\w*)/g)].map((m) => m[1] ?? m[2]);
    return values.length ? `" " ${values.join(' ')}` : '" "';
  });
  return codeOnly(kept);
}

/** The statement starting on a line, as far as its brackets go. */
function statementAt(file: SourceFile, line: number): string {
  let text = '';
  let depth = 0;
  for (let i = line - 1; i < Math.min(file.lines.length, line + 19); i++) {
    text += `${file.lines[i]}\n`;
    for (const ch of jvmCode(file.lines[i]!)) {
      if ('({['.includes(ch)) depth++;
      else if (')}]'.includes(ch)) depth--;
    }
    if (depth <= 0) break;
  }
  return text;
}

const KOTLIN_METHOD = /\bfun\s+(?:<[^>]+>\s*)?[\w.]+\s*\(/;
const JAVA_METHOD = /^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*[\w<>[\],?.][\w<>[\], ?.]*\s+\w+\s*\(/;
const NOT_A_JAVA_METHOD = /^\s*(?:return|new|throw|else|if|for|while|switch|try|catch|assert)\b|=\s*[^=]*\(/;

/** Kotlin says `fun`. Java has no keyword, so a line that declares a method has to be told from one that calls it. */
const isMethodStart = (file: SourceFile, text: string) =>
  /\.kt$/i.test(file.path) ? KOTLIN_METHOD.test(text) : JAVA_METHOD.test(text) && !NOT_A_JAVA_METHOD.test(text.replace(/@\w+\([^)]*\)/g, ''));

function methodStart(file: SourceFile, line: number): number {
  let start = line - 1;
  while (start > 0 && !isMethodStart(file, file.lines[start]!)) start--;
  return start;
}

/** The method around a line, with the annotations above it, to its closing brace or the end of its expression. */
function enclosing(file: SourceFile, line: number): string {
  const start = methodStart(file, line);
  let top = start;
  while (top > 0 && /^\s*@/.test(file.lines[top - 1]!)) top--;
  let depth = 0;
  let opened = false;
  let end = start;
  for (; end < file.lines.length && end < start + 300; end++) {
    for (const ch of jvmCode(file.lines[end]!)) {
      if (ch === '{') {
        depth++;
        opened = true;
      } else if (ch === '}') depth--;
    }
    if (end >= line - 1 && (opened ? depth <= 0 : true)) break;
  }
  return file.lines.slice(top, end + 1).join('\n');
}

const baseName = (file: SourceFile) => file.path.split('/').pop() ?? '';
/** A Feign interface calls someone else's endpoint, it doesn't serve one. */
const isClient = (file: SourceFile) => /@FeignClient\b/.test(file.text);

/** The annotations above the class: everything before the `class` keyword. */
const classHeader = (file: SourceFile) => {
  const at = file.lines.findIndex((l) => /^\s*(?:(?:public|internal|open|abstract|final|data)\s+)*class\s+\w+/.test(l));
  return at < 0 ? '' : file.lines.slice(0, at + 1).join('\n');
};

/* ---------- FX-OWN-001 ---------- */

const FIND_BY_ID = /\b\w*(?:[rR]epository|[rR]epo|[dD]ao|[sS]ervice|[mM]apper)\w*\s*\.\s*(?:findByIdOrNull|getReferenceById|getOne|findOne|(?:find|get|load|fetch)\w*ById)\s*\(\s*\w*[iI]d\b/;
const HANDLER = /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b/;
/** An ownership check on the method or class, or a principal it could compare the owner with. */
const OWNED = /@PreAuthorize|@PostAuthorize|@AuthenticationPrincipal|\bPrincipal\b|\bAuthentication\b|SecurityContextHolder|hasPermission|ownerId|userId|customerId|getOwner|\.owner\b|\.userId\b/;

/** Staff can see every customer's records. A folder called backend is usually the whole app, so it doesn't count. */
const STAFF_FILE = /(^|\/)(admin|backoffice|staff)\/|(^|\/)(Admin|Backoffice|Staff)\w*\.(java|kt)$/i;
/** A chart of accounts or a ledger is the bank's bookkeeping setup, not a customer's record. */
const BOOKKEEPING = /chartOf|ledger/i;

export const jvmOwnershipRule: FileRule = {
  id: 'FX-OWN-001',
  pack: 'fintech',
  appliesTo: JVM,
  skipTests: true,
  run(file) {
    if (STAFF_FILE.test(file.path)) return [];
    const out: Detection[] = [];
    const header = classHeader(file);
    eachLine(file, (text, line) => {
      const code = jvmCode(text);
      if (BOOKKEEPING.test(code)) return;
      // `repository.findById(id)` names no record, so the file has to say what it holds.
      if (!FIND_BY_ID.test(code) || !(MONEY.test(text) || (/\b(?:repository|repo|dao|service)\s*\./.test(code) && MONEY.test(baseName(file))))) return;
      const method = enclosing(file, line);
      if (HANDLER.test(method) && !OWNED.test(method) && !/@(?:PreAuthorize|PostAuthorize)/.test(header)) {
        out.push(hit(file, line, 'FX-OWN-001', 'critical', 'Money record read without an ownership check'));
      }
    });
    return out;
  },
};

/* ---------- FX-HOOK-001 ---------- */

const PROVIDER = /paystack|flutterwave|monnify|interswitch|remita|opay|kora/i;
const VERIFIED = /Mac\.getInstance|HmacSHA|HmacUtils|MessageDigest\.isEqual|x-paystack-signature|verif-hash|monnify-signature|verifySignature|validateSignature|webhook\w*secret/i;
const WEBHOOK_MAPPING = /@(?:Post|Request)Mapping\s*\([^)]*webhook/i;

export const jvmWebhookRule: FileRule = {
  id: 'FX-HOOK-001',
  pack: 'fintech',
  appliesTo: JVM,
  skipTests: true,
  run(file) {
    if (!PROVIDER.test(file.text) || VERIFIED.test(file.text) || isClient(file)) return [];
    const onClass = WEBHOOK_MAPPING.test(classHeader(file)) || /webhook/i.test(baseName(file));
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      const belongsToClass = onClass && line <= classHeader(file).split('\n').length;
      if (belongsToClass) return;
      if (WEBHOOK_MAPPING.test(text) || (onClass && /@PostMapping\b/.test(text))) out.push(hit(file, line, 'FX-HOOK-001', 'critical', 'Payment webhook without a signature check'));
    });
    return out;
  },
};

/* ---------- FX-TXN-001 ---------- */

const BALANCE_RMW = [
  // Java: wallet.setBalance(wallet.getBalance() - amount), or .subtract(amount), sometimes in extra brackets
  /\.set\w*Balance\s*\(\s*\(*\s*[\w.]*get\w*Balance\s*\(\s*\)\s*\)*\s*(?:[-+]|\.(?:add|subtract|plus|minus)\s*\()/,
  // Java: var balance = wallet.getBalance(); ... wallet.setBalance(balance.subtract(amount))
  /\.set\w*Balance\s*\(\s*\(*\s*\w*[bB]alance\w*\s*(?:[-+]|\.(?:add|subtract|plus|minus)\s*\()/,
  // Java: var newBalance = wallet.getBalance() - amount; ... wallet.setBalance(newBalance)
  /\.set\w*Balance\s*\(\s*(?:new|updated)\w*\s*\)/i,
  // Kotlin: wallet.balance = newBalance
  /\.\w*balance\s*=\s*(?:new|updated)\w*\s*$/i,
  // Kotlin: wallet.balance -= amount
  /\b[\w.]*balance\s*[-+]=/i,
  // Kotlin: wallet.balance = wallet.balance - amount, or .subtract(amount)
  /\b([\w.]*balance)\s*=\s*\1\s*(?:[-+]|\.(?:add|subtract|plus|minus)\s*\()/i,
];
const PERSISTS = /\.save\w*\s*\(|\.update\s*\(|\.persist\s*\(|\.merge\s*\(|\.execute\s*\(|\.executeUpdate\s*\(/;
const SAFE = /@Transactional|TransactionTemplate|transactionTemplate|PESSIMISTIC_WRITE|FOR UPDATE|forUpdate\s*\(/;

/** A helper that changes the balance in memory, for a caller in this class to save. */
const calledToSave = (file: SourceFile, line: number) => {
  const name = methodName(file.lines[methodStart(file, line)] ?? '');
  if (!name) return false;
  const call = new RegExp(`(?:^|[^.\\w]|\\bthis\\.)${name}\\s*\\(`);
  return file.lines.some((text, i) => call.test(jvmCode(text)) && methodStart(file, i + 1) !== methodStart(file, line) && PERSISTS.test(enclosing(file, i + 1)));
};

const methodName = (header: string) => {
  const line = header.replace(/@\w+(?:\([^)]*\))?/g, ' ');
  return (/\bfun\s+(?:<[^>]+>\s*)?(?:[\w.]+\.)?(\w+)\s*\(/.exec(line) ?? /(\w+)\s*\(/.exec(line))?.[1];
};

/** Whether a method is called from a transaction in this class, directly or through other methods. */
function calledInTransaction(file: SourceFile, start: number, depth = 3): boolean {
  const name = methodName(file.lines[start] ?? '');
  if (!name || depth === 0) return false;
  const call = new RegExp(`(?:^|[^.\\w]|\\bthis\\.)${name}\\s*\\(`);
  return file.lines.some((text, i) => {
    if (!call.test(jvmCode(text))) return false;
    const from = methodStart(file, i + 1);
    return from !== start && (SAFE.test(enclosing(file, i + 1)) || calledInTransaction(file, from, depth - 1));
  });
}

export const jvmBalanceRule: FileRule = {
  id: 'FX-TXN-001',
  pack: 'fintech',
  appliesTo: JVM,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    const header = classHeader(file);
    eachLine(file, (text, line) => {
      const code = jvmCode(text);
      if (!BALANCE_RMW.some((re) => re.test(code))) return;
      const method = enclosing(file, line);
      if (SAFE.test(method) || /@Transactional/.test(header) || calledInTransaction(file, methodStart(file, line))) return;
      if (PERSISTS.test(method) || calledToSave(file, line)) out.push(hit(file, line, 'FX-TXN-001', 'high', 'Balance update outside a transaction'));
    });
    return out;
  },
};

/* ---------- FX-PII-002 and FX-OTP-001 ---------- */

const LOG_CALL = /\b(?:log|LOG|logger|LOGGER|Log|Logger|kLogger)\s*\.\s*(?:trace|debug|info|warn|error|fatal|atInfo|atDebug|atWarn|atError)\s*\(|\bSystem\s*\.\s*(?:out|err)\s*\.\s*print\w*\s*\(|(?:^|\s)println\s*\(/;
const KYC_VALUE = /\b(?:get)?(?:bvn|nin|bvnNumber|ninNumber|bankVerificationNumber|nationalIdNumber|nationalId|bvn(?:Response|Data|Details|Record|Info)\w*)\b/i;
const OTP_VALUE = /\b(?:get)?(?:otp|otpCode|oneTimePassword|passcode|verificationCode)\b/i;
const MASKED = /mask|redact|last4|takeLast\s*\(\s*4|\.substring\s*\([^)]*length\s*\(\s*\)\s*-\s*4|\*\*\*/i;
/** `user.getBvn() != null`, `user.bvn.isNullOrEmpty()` and `.length()` say whether it's there, not what it is. */
const withoutPresence = (code: string) =>
  code
    .replace(/[\w.()]+\s*(?:!=|==|!==|===)\s*null\b/g, ' ')
    .replace(/[\w.()?]+\.(?:isEmpty|isBlank|isNullOrEmpty|isNullOrBlank|isNotEmpty|isNotBlank|length)\s*\(\s*\)/g, ' ')
    .replace(/[\w.()?]+\.length\b/g, ' ');

export const jvmKycLoggingRule: FileRule = {
  id: 'FX-PII-002',
  pack: 'fintech',
  appliesTo: JVM,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (!LOG_CALL.test(text)) return;
      const code = withoutPresence(jvmCode(statementAt(file, line)));
      if (KYC_VALUE.test(code) && !MASKED.test(code)) out.push(hit(file, line, 'FX-PII-002', 'high', 'BVN or NIN written to logs'));
    });
    return out;
  },
};

const WEAK_RANDOM = /\bnew\s+Random\s*\(|(?:^|[^.\w])Random\s*\(|\bMath\.random\s*\(|\bThreadLocalRandom\.current\s*\(|\bRandom\.next\w*\s*\(|\)\s*\.random\s*\(|\bRandomStringUtils\.\w+\s*\(/;
/** In code with no sigil, `pin` must be a word: shipping and mapping aren't secrets, and neither is a zipCode. */
const SECRET_NAME = /(?:\b|_)(?:otp|pin|passcode|token|OTP|PIN|TOKEN)(?![a-z])|(?<=[a-z])(?:Otp|Pin|Passcode|Token)(?![a-z])|\bcode\b|(?:[aA]uth|[vV]erif\w*|[sS]ms|SMS|[rR]eset|[lL]ogin|[cC]onfirm\w*|[sS]ecurity|[aA]ctivation|[mM]fa|MFA)_?[cC]ode\b/;
/** private static final Random RANDOM = new Random(), used somewhere else in the file. */
const weakRandomNames = (file: SourceFile) =>
  [...jvmCode(file.text).matchAll(/\b(?:Random\s+|va[lr]\s+)(\w+)\s*(?::\s*Random\s*)?=\s*(?:new\s+)?Random\s*\(/g)].map((m) => m[1]!);
const OFFER = /coupon|promo|voucher|discount|referral|invite|colou?r|hash[cC]ode|postal|zip|status/i;
const RESPONSE = /\bResponseEntity\s*\.|\bMap\.of\s*\(|\bmapOf\s*\(/;

export const jvmOtpRule: FileRule = {
  id: 'FX-OTP-001',
  pack: 'fintech',
  appliesTo: JVM,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    const weakNames = weakRandomNames(file);
    const flaggedMethods = new Set<number>();
    eachLine(file, (text, line) => {
      const code = jvmCode(text);
      const nearby = `${jvmCode(file.lines.slice(Math.max(0, line - 3), line).join('\n'))}\n${jvmCode(file.lines[methodStart(file, line)] ?? '')}`;
      const isWeak = WEAK_RANDOM.test(code) || weakNames.some((name) => new RegExp(`\\b${name}\\.next\\w*\\(`).test(code));
      if (isWeak && SECRET_NAME.test(nearby) && !OFFER.test(nearby)) {
        // Random random = new Random() and then random.nextInt(10) are one problem, not two.
        if (!flaggedMethods.has(methodStart(file, line))) out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP generated with java.util.Random or Math.random'));
        flaggedMethods.add(methodStart(file, line));
        return;
      }
      if (LOG_CALL.test(text)) {
        const stmt = statementAt(file, line);
        const inner = jvmCode(stmt);
        if (OTP_VALUE.test(inner) && !MASKED.test(inner)) out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP written to logs'));
        else if (/\botp\b[^\n]{0,20}?\b\d{4,8}\b/i.test(stmt)) out.push(hit(file, line, 'FX-OTP-001', 'medium', 'Hard-coded OTP in source'));
        return;
      }
      // Map.of("otp", otp) and mapOf("otp" to otp): the name is in a string.
      if (RESPONSE.test(code) && /"(?:otp|otpCode)"\s*(?:,|to\b)/.test(statementAt(file, line))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP returned in an API response'));
      }
    });
    return out;
  },
};

/* ---------- FX-IDEM-001 ---------- */

const MAPPING = /@(Post|Put|Request)Mapping\b/;
/** The route in a mapping: its first argument, or value = or path = wherever they are. */
const routeOf = (annotation: string) => /@\w+\s*\(\s*[{[]?\s*"([^"]*)"/.exec(annotation)?.[1] ?? /\b(?:value|path)\s*=\s*[{[]?\s*"([^"]*)"/.exec(annotation)?.[1] ?? '';
/** A path segment that moves money. `payout-processors` is a settings page, and `/payouts/{id}/mark` moves nothing. */
const MOVES_MONEY = /(?:^|\/)(?:transfers?|payouts?|withdraw(?:als?)?|disburse(?:ments?)?|send-?money)(?:\/\{[^}]*\})*\/?$/i;
const READ_ONLY = /\/(?:quote|quotes|fees?|preview|estimate|validate|verify|lookup|name-?enquiry|resolve)\/?$/i;
const GUARD = /idempot|dedup|replay/i;

export const jvmIdempotencyRule: FileRule = {
  id: 'FX-IDEM-001',
  pack: 'fintech',
  appliesTo: JVM,
  skipTests: true,
  run(file) {
    if (/idempoten/i.test(file.text) || isClient(file)) return [];
    const headerLines = classHeader(file).split('\n').length;
    const onClass = routeOf(/@RequestMapping\b[^\n]*/.exec(classHeader(file))?.[0] ?? '');
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (line <= headerLines) return;
      const match = MAPPING.exec(text);
      if (!match) return;
      const annotation = statementAt(file, line);
      // @RequestMapping only counts when it says POST or PUT.
      if (match[1] === 'Request' && !/RequestMethod\.(?:POST|PUT)/.test(annotation)) return;
      const own = routeOf(annotation);
      const route = `${onClass}/${own}`.replace(/\/+/g, '/');
      if (!MOVES_MONEY.test(route) || READ_ONLY.test(`/${own}`)) return;
      const around = file.lines.slice(Math.max(0, line - 3), line + 2).join('\n');
      if (!GUARD.test(around)) out.push(hit(file, line, 'FX-IDEM-001', 'high', 'Transfer without an idempotency key'));
    });
    return out;
  },
};

export const JVM_FINTECH_RULES: FileRule[] = [jvmOwnershipRule, jvmWebhookRule, jvmBalanceRule, jvmKycLoggingRule, jvmOtpRule, jvmIdempotencyRule];
