import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored, JS_TS } from './types';

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
  run(file) {
    const out: Detection[] = [];
    const byId =
      /\.(findById|findByPk|findUnique|findOne|findFirst|get|getById|load)\s*\(\s*(\{\s*(where\s*:\s*\{\s*)?(_?id|uuid)\s*:\s*)?(Number\(|parseInt\()?\s*(req|request|ctx\.request|ctx)\.(params|query|body)\b/;
    const sqlById = /(select|update|delete)\b[^;]*\bwhere\b[^;]*\bid\s*=\s*(\$\d|\?|:id)/i;
    file.lines.forEach((text, i) => {
      const line = i + 1;
      const looksById = byId.test(text) || (sqlById.test(text) && /req\.(params|query|body)/.test(window(file, line, 2, 3)));
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
  run(file) {
    const rmw = /\b([\w.]*balance)\s*=\s*\(?\s*(Number\()?\s*[\w.]*balance\)?\s*[-+]|\b[\w.]*balance\s*[-+]=/i;
    const safe = /\$transaction|\.transaction\s*\(|startTransaction|BEGIN\b|FOR UPDATE|\$inc\b|increment\s*\(|decrement\s*\(|sequelize\.transaction|knex\.transaction|withTransaction/i;
    if (safe.test(file.text)) return [];
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      if (rmw.test(text) && !isIgnored(file, i + 1)) {
        out.push(hit(file, i + 1, 'FX-TXN-001', 'high', 'Balance update outside a transaction'));
      }
    });
    return out;
  },
};

/** FX-PII-002: BVN or NIN written to logs. */
export const kycLoggingRule: FileRule = {
  id: 'FX-PII-002',
  pack: 'fintech',
  appliesTo: JS_TS,
  run(file) {
    const logCall = /\b(console\.(log|info|warn|error|debug)|logger\.(log|info|warn|error|debug|trace)|log\.(info|warn|error|debug)|winston\.\w+|pino\.\w+)\s*\(/;
    const kyc = /\b(bvn|nin|bvnNumber|ninNumber|bankVerificationNumber|nationalId)\b/i;
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      if (logCall.test(text) && kyc.test(text) && !/mask|redact|last4|slice\(-4\)/i.test(text) && !isIgnored(file, i + 1)) {
        out.push(hit(file, i + 1, 'FX-PII-002', 'high', 'BVN or NIN written to logs'));
      }
    });
    return out;
  },
};

/** FX-OTP-001: OTPs generated with Math.random, or logged / returned. */
export const otpRule: FileRule = {
  id: 'FX-OTP-001',
  pack: 'fintech',
  appliesTo: JS_TS,
  run(file) {
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      const line = i + 1;
      if (isIgnored(file, line)) return;
      if (/Math\.random\s*\(/.test(text) && /\b(otp|pin|token|code|passcode|verification)\b/i.test(window(file, line, 1, 1))) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP generated with Math.random'));
      } else if (/\b(console\.\w+|logger\.\w+)\s*\(/.test(text) && /\botp\b/i.test(text)) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP written to logs'));
      } else if (/res\.(json|send)\s*\(/.test(text) && /\botp\s*[:,}]/i.test(text)) {
        out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP returned in an API response'));
      }
    });
    return out;
  },
};

/** FX-IDEM-001: a money-out route with no idempotency key handling anywhere in the file. */
export const idempotencyRule: FileRule = {
  id: 'FX-IDEM-001',
  pack: 'fintech',
  appliesTo: JS_TS,
  run(file) {
    if (/idempoten/i.test(file.text)) return [];
    const route = /\.(post|put)\s*\(\s*["'`][^"'`]*(transfer|payout|withdraw|disburse|send-money|sendmoney)[^"'`]*["'`]/i;
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      if (route.test(text) && !isIgnored(file, i + 1)) {
        out.push(hit(file, i + 1, 'FX-IDEM-001', 'high', 'Transfer without an idempotency key'));
      }
    });
    return out;
  },
};

export const FINTECH_RULES: FileRule[] = [ownershipRule, webhookSignatureRule, balanceRaceRule, kycLoggingRule, otpRule, idempotencyRule];
