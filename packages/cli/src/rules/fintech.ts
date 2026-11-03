import type { Detection, FileRule, SourceFile } from './types';
import { codeOnly, isIgnored, JS_TS, statementAt } from './types';

/*
 * Fintech rules for JavaScript and TypeScript. They are deliberately conservative pattern
 * checks: each looks for a specific risky shape and the absence of the usual safeguard nearby.
 * Silence a reviewed line with `// fortis-ignore`.
 */

const MONEY = /transfer|wallet|account|payout|withdraw|transaction|payment|balance|loan|disburse|beneficiar|card|invoice/i;
const OWNER_SCOPE = /\b(user|owner|customer|account|wallet|merchant|tenant|org)_?id\b|req\.user|ctx\.state\.user|request\.user|session\.user|currentUser|res\.locals\.user/i;

function window(file: SourceFile, line: number, before: number, after: number): string {
  return file.lines.slice(Math.max(0, line - 1 - before), line + after).join('\n');
}

function hit(file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string): Detection {
  return { ruleId, severity, title, file: file.path, line, snippet: (file.lines[line - 1] ?? '').trim() };
}

/** FX-OWN-001: loading a money record by an ID from the request without scoping it to the signed-in user. */
export const ownershipRule: FileRule = {
  id: 'FX-OWN-001',
  pack: 'fintech',
  appliesTo: JS_TS,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    const byId =
      /\.(findById|findByPk|findUnique|findOne|findFirst|get|getById|load)\s*\(\s*(\{\s*(where\s*:\s*\{\s*)?(_?id|uuid)\s*:\s*)?(Number\(|parseInt\()?\s*(req|request|ctx\.request|ctx)\.(params|query|body)\b/;
    const sqlById = /(select|update|delete)\b[^;]*\bwhere\b[^;]*\bid\s*=\s*(\$\d|\?|:id)/i;
    // NestJS: `@Param('id') id` in the handler signature, then a lookup by that bare id.
    const nestById = /\.(findUnique|findFirst|findOne|findById|findByPk|findOneBy)\s*\(\s*(\{\s*(where\s*:\s*)?\{\s*id\s*\}|\{\s*id\s*\}|id\s*[,)])/;
    file.lines.forEach((text, i) => {
      const line = i + 1;
      const nest = nestById.test(text) && /@Param\(\s*["'`]id["'`]\s*\)\s*id\b/.test(window(file, line, 8, 0));
      const looksById = nest || byId.test(text) || (sqlById.test(text) && /req\.(params|query|body)/.test(window(file, line, 2, 3)));
      if (!looksById) return;
      const context = window(file, line, 3, 6);
      if (!MONEY.test(`${file.path}\n${context}`)) return;
      if (OWNER_SCOPE.test(context.replace(text, '')) || OWNER_SCOPE.test(text.replace(/(req|request|ctx)\.(params|query|body)\.\w+/g, ''))) return;
      if (isIgnored(file, line)) return;
      out.push(hit(file, line, 'FX-OWN-001', 'critical', 'Money record read without an ownership check'));
    });
    return out;
  },
};

/** FX-HOOK-001: a payment-provider webhook handler that never verifies the signature. */
export const webhookSignatureRule: FileRule = {
  id: 'FX-HOOK-001',
  pack: 'fintech',
  appliesTo: JS_TS,
  skipTests: true,
  run(file) {
    const route = /\.(post|all|use)\s*\(\s*["'`][^"'`]*webhook[^"'`]*["'`]/i;
    const provider = /paystack|flutterwave|monnify|interswitch|remita|opay|kora/i;
    const verified = /x-paystack-signature|verif-hash|monnify-signature|createHmac|verifySignature|validateSignature|timingSafeEqual|webhook.*secret/i;
    if (!provider.test(file.text) || verified.test(file.text)) return [];
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      if (route.test(text) && !isIgnored(file, i + 1)) {
        out.push(hit(file, i + 1, 'FX-HOOK-001', 'critical', 'Payment webhook without a signature check'));
      }
    });
    return out;
  },
};

/** FX-TXN-001: a read-modify-write of a balance outside a transaction or atomic update. */
export const balanceRaceRule: FileRule = {
  id: 'FX-TXN-001',
  pack: 'fintech',
  appliesTo: JS_TS,
  skipTests: true,
  run(file) {
    const rmw = /\b([\w.]*balance)\s*=\s*\(?\s*(Number\()?\s*[\w.]*balance\)?\s*[-+]|\b[\w.]*balance\s*[-+]=/i;
    const safe = /\$transaction|\.transaction\s*\(|startTransaction|BEGIN\b|FOR UPDATE|\$inc\b|increment\s*\(|decrement\s*\(|sequelize\.transaction|knex\.transaction|withTransaction/i;
    // Only a balance that is written back to storage can race.
    const persists = /\.save\s*\(|\.(updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|upsert)\s*\(|\.update\s*\(\s*\{|\.query\s*\(|\.execute\s*\(|\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bprisma\.|\bknex\b|getRepository|\.repository\b/i;
    // UI components compute running balances for display; they cannot race on stored money.
    if (/\.[jt]sx$/i.test(file.path) || safe.test(file.text) || !persists.test(file.text)) return [];
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      if (rmw.test(text) && !isIgnored(file, i + 1)) {
        out.push(hit(file, i + 1, 'FX-TXN-001', 'high', 'Balance update outside a transaction'));
      }
    });
    return out;
  },
};

/** FX-PII-002: a BVN or NIN *value* written to logs (not just the word "BVN" in a message). */
const LOG_CALL = /\b(console\.(log|info|warn|error|debug)|logger\.(log|info|warn|error|debug|trace)|log\.(info|warn|error|debug)|winston\.\w+|pino\.\w+)\s*\(/;
const KYC_VALUE = /\b(bvn|nin|bvnNumber|ninNumber|bankVerificationNumber|nationalIdNumber|nationalId)\b/i;
const MASKED = /mask|redact|last4|slice\(\s*-4\s*\)|\*\*\*/i;

/** `Boolean(c.bvn)`, `!!c.bvn` and `c.bvn != null` log whether a value exists, not the value. */
function withoutPresenceChecks(code: string): string {
  return code
    .replace(/\bBoolean\s*\([^)]*\)/g, ' ')
    .replace(/!!\s*[\w.?]+/g, ' ')
    .replace(/[\w.?]+\s*(?:!==?|===?)\s*(?:null|undefined)\b/g, ' ')
    .replace(/[\w.?]+\.length\b/g, ' ')
    // `p.bvn ? 'set' : 'missing'` (string branches are already blanked by codeOnly)
    .replace(/[\w.?]+\s*\?(?![.?])(?=\s*[ :]*\s*(?:[ :]|$))/g, ' ');
}

export const kycLoggingRule: FileRule = {
  id: 'FX-PII-002',
  pack: 'fintech',
  appliesTo: JS_TS,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      if (!LOG_CALL.test(text) || isIgnored(file, i + 1)) return;
      const code = withoutPresenceChecks(codeOnly(statementAt(file, i + 1)));
      if (KYC_VALUE.test(code) && !MASKED.test(code)) {
        out.push(hit(file, i + 1, 'FX-PII-002', 'high', 'BVN or NIN written to logs'));
      }
    });
    return out;
  },
};

/** FX-OTP-001: OTPs generated with Math.random, an OTP value logged or returned, or a hard-coded OTP. */
const OTP_VALUE = /\b(otp|otpCode|oneTimePassword|passcode|verificationCode)\b/i;

export const otpRule: FileRule = {
  id: 'FX-OTP-001',
  pack: 'fintech',
  appliesTo: JS_TS,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      const line = i + 1;
      if (isIgnored(file, line)) return;
      if (/Math\.random\s*\(/.test(text) && /\b(otp|pin|token|code|passcode|verification)\b/i.test(window(file, line, 1, 1))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP generated with Math.random'));
        return;
      }
      if (LOG_CALL.test(text)) {
        const stmt = statementAt(file, line);
        const code = codeOnly(stmt);
        if (OTP_VALUE.test(code) && !MASKED.test(code)) {
          out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP written to logs'));
        } else if (/\botp\b[^\n]{0,20}?\b\d{4,8}\b/i.test(stmt)) {
          out.push(hit(file, line, 'FX-OTP-001', 'medium', 'Hard-coded OTP in source'));
        }
        return;
      }
      if (/res\.(json|send)\s*\(/.test(text) && /\botp\s*[:,}]/i.test(codeOnly(statementAt(file, line)))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP returned in an API response'));
      }
    });
    return out;
  },
};

/**
 * FX-IDEM-001: a money-out route with no idempotency protection: none in the file, no
 * guard-style middleware on the route, and no helper from an idempotency module.
 */
export const idempotencyRule: FileRule = {
  id: 'FX-IDEM-001',
  pack: 'fintech',
  appliesTo: JS_TS,
  skipTests: true,
  run(file, ctx) {
    if (/idempoten/i.test(file.text)) return [];
    // A route is registered with a path literal ("/..." or ":id"); outbound calls like axios.post(`${BASE}/...`) are not routes.
    const route = /\.(post|put)\s*\(\s*["'`][/:][^"'`$]*(transfer|payout|withdraw|disburse|send-money|sendmoney)[^"'`]*["'`]/i;
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      if (!route.test(text) || isIgnored(file, i + 1)) return;
      // Read-only helpers next to money routes (fee quotes, name enquiry) move no money.
      if (/["'`][^"'`]*\/(quote|quotes|fees?|preview|estimate|validate|verify|lookup|name-?enquiry|resolve)["'`/?]/i.test(text)) return;
      const stmt = statementAt(file, i + 1).slice(0, 600);
      const names = codeOnly(stmt).match(/[A-Za-z_$][\w$]*/g) ?? [];
      if (names.some((n) => /idempot|dedup|replay|paymentguard|withguard/i.test(n) || ctx.idempotencyHelpers.has(n))) return;
      out.push(hit(file, i + 1, 'FX-IDEM-001', 'high', 'Transfer without an idempotency key'));
    });
    return out;
  },
};

export const FINTECH_RULES: FileRule[] = [ownershipRule, webhookSignatureRule, balanceRaceRule, kycLoggingRule, otpRule, idempotencyRule];
