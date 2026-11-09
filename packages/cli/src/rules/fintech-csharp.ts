import type { Detection, FileRule, SourceFile } from './types';
import { codeOnly, isIgnored, statementAt } from './types';

/*
 * The fintech rules for C#: ASP.NET Core controllers and minimal APIs, with Entity Framework. Same
 * rule IDs as the other languages, so they share compliance mapping and the dashboard. Line patterns,
 * conservative like the rest. Silence a reviewed line with `// fortis-ignore`.
 */

export const CSHARP = /\.cs$/i;

const MONEY = /transfer|wallet|account|payout|withdraw|deposit|transaction|payment|balance|loan|disburse|beneficiar|card|invoice|ledger|savings|statement/i;

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

/** Code with strings blanked out, but the values in $"..." kept: $"BVN {user.Bvn}" keeps user.Bvn. */
export function csCode(text: string): string {
  const kept = text.replace(/\$@?"((?:[^"\\]|\\.)*)"|@\$"((?:[^"\\]|\\.)*)"/g, (_, a?: string, b?: string) => ` ${[...(a ?? b ?? '').matchAll(/\{([^{}]+)\}/g)].map((m) => m[1]).join(' ')} `);
  return codeOnly(kept);
}

const MEMBER = /^\s*(?:\[\s*Http\w+|\[\s*Route|(?:public|private|protected|internal)\b[^=;]*\(|(?:\w+\.)?Map(?:Get|Post|Put|Patch|Delete)\s*\()/;

/** The method, or minimal API handler, around a line. */
function enclosing(file: SourceFile, line: number): string {
  let start = line - 1;
  while (start > 0 && !MEMBER.test(file.lines[start]!)) start--;
  // Attributes sit above the method they belong to.
  while (start > 0 && /^\s*\[/.test(file.lines[start - 1]!)) start--;
  let depth = 0;
  let opened = false;
  let end = start;
  for (; end < file.lines.length && end < start + 200; end++) {
    for (const ch of codeOnly(file.lines[end]!)) {
      if (ch === '{') {
        depth++;
        opened = true;
      } else if (ch === '}') depth--;
    }
    if (end >= line - 1 && ((opened && depth <= 0) || (!opened && /;\s*$/.test(file.lines[end]!)))) break;
  }
  return file.lines.slice(start, end + 1).join('\n');
}

/* ---------- FX-OWN-001 ---------- */

const FIND_BY_ID = /\.(?:FindAsync|Find|GetByIdAsync|GetById)\s*\(\s*\w*[iI]d\b|\.(?:First|FirstOrDefault|Single|SingleOrDefault|Where|Any)(?:Async)?\s*\(\s*(\w+)\s*=>\s*\1\.Id\s*==\s*\w+\s*\)/;
const IS_ENDPOINT = /\[\s*Http(?:Get|Post|Put|Patch|Delete)|\bMap(?:Get|Post|Put|Patch|Delete)\s*\(/;
/** Filtering by the signed-in user, or resource-based authorization. [Authorize] alone only says someone is logged in. */
const OWNED = /UserId|OwnerId|CustomerId|TenantId|AccountHolderId|ClaimTypes\.|FindFirst|GetUserId|User\.Identity|AuthorizeAsync|currentUser/i;

export const csOwnershipRule: FileRule = {
  id: 'FX-OWN-001',
  pack: 'fintech',
  appliesTo: CSHARP,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (!FIND_BY_ID.test(text)) return;
      const member = enclosing(file, line);
      // [AllowAnonymous] is a stated decision that this is public, like a checkout page with an unguessable ID.
      if (IS_ENDPOINT.test(member) && MONEY.test(`${file.path}\n${member}`) && !OWNED.test(member) && !/\[\s*AllowAnonymous\b/.test(member)) {
        out.push(hit(file, line, 'FX-OWN-001', 'critical', 'Money record read without an ownership check'));
      }
    });
    return out;
  },
};

/* ---------- FX-HOOK-001 ---------- */

const WEBHOOK_ROUTE = /\[\s*(?:HttpPost|Route)\s*\(\s*"[^"]*webhook[^"]*"|\bMapPost\s*\(\s*"[^"]*webhook[^"]*"/i;
const PROVIDER = /paystack|flutterwave|monnify|interswitch|remita|opay|kora/i;
const VERIFIED = /FixedTimeEquals|HMACSHA\d+|x-paystack-signature|verif-hash|monnify-signature|VerifySignature|ValidateSignature|VerifyWebhook|Webhook\w*Secret/i;

export const csWebhookRule: FileRule = {
  id: 'FX-HOOK-001',
  pack: 'fintech',
  appliesTo: CSHARP,
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

const BALANCE_RMW = /\b[\w.]*Balance\s*[-+]=|\b([\w.]*Balance)\s*=\s*\1\s*[-+]/i;
const PERSISTS = /SaveChanges(?:Async)?\s*\(|ExecuteSql|\.Update\s*\(/;
/** A row version also makes this safe: the save fails if another request changed the row first. */
const SAFE = /BeginTransaction|TransactionScope|ExecuteUpdate|SetProperty|FOR UPDATE|UPDLOCK|\[ConcurrencyCheck\]|\[Timestamp\]|IsRowVersion|IsConcurrencyToken/;

export const csBalanceRule: FileRule = {
  id: 'FX-TXN-001',
  pack: 'fintech',
  appliesTo: CSHARP,
  skipTests: true,
  run(file) {
    if (SAFE.test(file.text) || !PERSISTS.test(file.text)) return [];
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (BALANCE_RMW.test(codeOnly(text))) out.push(hit(file, line, 'FX-TXN-001', 'high', 'Balance update outside a transaction'));
    });
    return out;
  },
};

/* ---------- FX-PII-002 and FX-OTP-001 ---------- */

const LOG_CALL = /\b(?:\w*[lL]ogger|Log)\.(?:Log\w*|Verbose|Debug|Information|Warning|Error|Fatal|Trace|Info|Warn)\s*\(|\bConsole\.(?:Write|WriteLine|Error\.WriteLine)\s*\(|\bDebug\.WriteLine\s*\(|\bTrace\.\w+\s*\(/;
const KYC_VALUE = /\b(?:bvn|nin|bvnNumber|ninNumber|bankVerificationNumber|nationalIdNumber|nationalId)\b/i;
const OTP_VALUE = /\b(?:otp|otpCode|oneTimePassword|passcode|verificationCode)\b/i;
const MASKED = /mask|redact|last4|\[\^4\.\.\]|\*\*\*/i;
/** `string.IsNullOrEmpty(c.Bvn)`, `c.Bvn != null` and `c.Bvn.Length` say whether it's there, not what it is. */
const withoutPresence = (code: string) =>
  code
    .replace(/string\.IsNullOr\w+\s*\([^)]*\)/g, ' ')
    .replace(/[\w.?]+\s*(?:!=|==|is not|is)\s*null\b/g, ' ')
    .replace(/[\w.?]+\.Length\b/g, ' ');

export const csKycLoggingRule: FileRule = {
  id: 'FX-PII-002',
  pack: 'fintech',
  appliesTo: CSHARP,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      if (!LOG_CALL.test(text)) return;
      const code = withoutPresence(csCode(statementAt(file, line)));
      if (KYC_VALUE.test(code) && !MASKED.test(code)) out.push(hit(file, line, 'FX-PII-002', 'high', 'BVN or NIN written to logs'));
    });
    return out;
  },
};

const WEAK_RANDOM = /\bnew Random\s*\(|\bRandom\.Shared\b|\b\w*(?:random|rand|rng)\w*\.Next\s*\(/i;
const SECRET_NAME = /\b\w*(?:otp|pin|token|code|passcode|verification)\w*\b/i;
const RESPONSE = /\b(?:Ok|Json|Created|Results\.Ok|Results\.Json|TypedResults\.Ok)\s*\(/;

export const csOtpRule: FileRule = {
  id: 'FX-OTP-001',
  pack: 'fintech',
  appliesTo: CSHARP,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      const code = codeOnly(text);
      if (WEAK_RANDOM.test(code) && !/RandomNumberGenerator/.test(code) && SECRET_NAME.test(file.lines.slice(Math.max(0, line - 2), line + 1).join('\n'))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP generated with System.Random'));
        return;
      }
      if (LOG_CALL.test(text)) {
        const stmt = statementAt(file, line);
        const inner = csCode(stmt);
        if (OTP_VALUE.test(inner) && !MASKED.test(inner)) out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP written to logs'));
        else if (/\botp\b[^\n]{0,20}?\b\d{4,8}\b/i.test(stmt)) out.push(hit(file, line, 'FX-OTP-001', 'medium', 'Hard-coded OTP in source'));
        return;
      }
      if (RESPONSE.test(code) && /\bnew\s*\{[^}]*\b(?:otp|otpCode)\b/i.test(codeOnly(statementAt(file, line)))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP returned in an API response'));
      }
    });
    return out;
  },
};

/* ---------- FX-IDEM-001 ---------- */

/** A path segment that moves money. `payout-processors` is a settings page, and `/payouts/{id}/mark` moves nothing. */
export const MOVES_MONEY = /(?:^|\/)(?:transfers?|payouts?|withdraw(?:als?)?|disburse(?:ments?)?|send-?money)(?:\/\{[^}]*\}|\/:[^/]+)*\/?$/i;
const ATTRIBUTE_ROUTE = /\[\s*Http(?:Post|Put)\s*(?:\(\s*"([^"]*)"\s*\))?\s*\]/;
const MAP_ROUTE = /\bMap(?:Post|Put)\s*\(\s*"([^"]*)"/;
const CLASS_ROUTE = /\[\s*Route\s*\(\s*"([^"]*)"\s*\)\s*\]/;
const READ_ONLY = /\/?(?:quote|quotes|fees?|preview|estimate|validate|verify|lookup|name-?enquiry|resolve)\/?$/i;
const GUARD = /Idempot|Dedup|Replay/i;

export const csIdempotencyRule: FileRule = {
  id: 'FX-IDEM-001',
  pack: 'fintech',
  appliesTo: CSHARP,
  skipTests: true,
  run(file) {
    if (/idempoten/i.test(file.text)) return [];
    const classRoute = file.lines.map((l) => CLASS_ROUTE.exec(l)?.[1]).find(Boolean) ?? '';
    // [Route("api/[controller]")] takes its name from the class.
    const controller = /\bclass\s+(\w+?)Controller\b/.exec(file.text)?.[1] ?? '';
    const base = classRoute.replace('[controller]', controller);
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      const attribute = ATTRIBUTE_ROUTE.exec(text);
      const mapped = MAP_ROUTE.exec(text);
      if (!attribute && !mapped) return;
      const own = (attribute ? attribute[1] : mapped![1]) ?? '';
      // A leading ~/ replaces the class's route.
      const route = attribute ? (own.startsWith('~') ? own : `${base}/${own}`) : own;
      if (!MOVES_MONEY.test(route) || READ_ONLY.test(own)) return;
      // A guard attribute sits above or below the route, and a guard filter chains on after it.
      const around = file.lines.slice(Math.max(0, line - 3), line + 2).join('\n');
      if (!GUARD.test(around)) out.push(hit(file, line, 'FX-IDEM-001', 'high', 'Transfer without an idempotency key'));
    });
    return out;
  },
};

export const CSHARP_FINTECH_RULES: FileRule[] = [csOwnershipRule, csWebhookRule, csBalanceRule, csKycLoggingRule, csOtpRule, csIdempotencyRule];
