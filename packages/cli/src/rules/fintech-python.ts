import { acceptsWrites, isRequestHandler, PYTHON, pyClasses, pyCodeOnly, pyFunctions, pyStatementAt, routePath, type PyFunction } from './python';
import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored } from './types';

/*
 * The fintech rules for Python: Django with Django REST, Flask and FastAPI, on the Django ORM,
 * SQLAlchemy and raw SQL. Same rule IDs as JavaScript, so they share compliance mapping and
 * the dashboard. Conservative, like the JavaScript rules: each looks for a specific risky
 * shape and the absence of the usual safeguard. Silence a reviewed line with `# fortis-ignore`.
 */

const MONEY = /transfer|wallet|account|payout|withdraw|deposit|transaction|payment|balance|loan|disburse|beneficiar|card|invoice|expense|income|ledger|savings|statement|receipt/i;

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
});

/** Each line of a function's body, with its 1-based line number. */
function bodyLines(file: SourceFile, fn: PyFunction): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  for (let n = fn.bodyLine; n <= fn.endLine; n++) out.push({ line: n, text: file.lines[n - 1] ?? '' });
  return out;
}

/* ---------- FX-OWN-001: a money record loaded by an ID from the request, for anyone who asks ---------- */

const BY_ID = [
  /\.objects\.(?:get|filter)\s*\(\s*(?:pk|id|uuid)\s*=\s*(.+)/,
  /\bget_object_or_404\s*\(\s*\w+\s*,\s*(?:pk|id|uuid)\s*=\s*(.+)/,
  /\b(?:\w*session|db|database)\.get\s*\(\s*\w+\s*,\s*(.+)/,
  /\.query\.(?:get|get_or_404)\s*\(\s*(.+)/,
  /\.query\s*\(\s*\w+\s*\)\.get\s*\(\s*(.+)/,
  /\.filter_by\s*\(\s*(?:id|uuid)\s*=\s*(.+)/,
  /\.(?:filter|where)\s*\(\s*\w+\.(?:id|uuid)\s*==\s*(.+)/,
];
const SQL_BY_ID = /\b(?:select|update|delete)\b.*\bwhere\s+(?:\w+\.)?id\s*=\s*(?:%s|\?|:\w+|%\(\w+\)s)/i;
/** Tied to the signed-in user. `request.user.is_authenticated` only says someone is signed in, not who owns what. */
const OWNER_SCOPE = /request\.user|current_user|\bg\.user|\buser_id\b|\bowner(_id)?\s*=|\bcustomer(_id)?\s*=|\buser\s*=|\buser\.id\b|\bcheck_object_permissions\b|\bget_queryset\b/;
const ADMIN_ONLY = /staff_member_required|\badmin_required\b|IsAdminUser|\bis_staff\b|\bis_superuser\b|\/admin\//;

/** Neither says who owns the record: `request.user.is_authenticated`, or `expense.owner = request.user` when saving it. */
const withoutNonChecks = (code: string) =>
  code
    .replace(/\b(?:request\.user|current_user|\w*user)\.is_authenticated\b/g, ' ')
    .replace(/^\s*\w+\.\w+\s*=\s*(?:request\.user|current_user|g\.user)\b.*$/gm, ' ');

/** The lookup uses something the caller controls: a URL parameter or the request itself. */
function fromRequest(value: string, fn: PyFunction): boolean {
  if (/\brequest\.|\bkwargs\b/.test(value)) return true;
  return fn.params.some((p) => p !== 'request' && new RegExp(`\\b${p}\\b`).test(value));
}

function ownershipInFunctions(file: SourceFile): Detection[] {
  const out: Detection[] = [];
  for (const fn of pyFunctions(file)) {
    if (!isRequestHandler(fn)) continue;
    const decorators = fn.decorators.map((d) => d.text).join('\n');
    if (ADMIN_ONLY.test(`${decorators}\n${fn.name}\n${fn.body}\n${fn.classBases ?? ''}`)) continue;
    if (OWNER_SCOPE.test(withoutNonChecks(pyCodeOnly(fn.body)))) continue;
    for (const { line, text } of bodyLines(file, fn)) {
      const code = pyCodeOnly(text);
      const byId = BY_ID.map((re) => re.exec(code)?.[1]).find(Boolean);
      const lookup = byId !== undefined ? fromRequest(byId, fn) : SQL_BY_ID.test(text) && fn.params.some((p) => p !== 'request');
      if (!lookup) continue;
      if (!MONEY.test(`${file.path}\n${fn.name}\n${text}\n${fn.className ?? ''}`)) continue;
      if (isIgnored(file, line)) continue;
      out.push(hit(file, line, 'FX-OWN-001', 'critical', 'Money record read without an ownership check'));
    }
  }
  return out;
}

/** Django REST: `queryset = Wallet.objects.all()` on a view, which serves any record to anyone signed in. */
function ownershipInViewSets(file: SourceFile): Detection[] {
  const out: Detection[] = [];
  const singleRecord = /ModelViewSet|Retrieve\w*APIView|Update\w*APIView|Destroy\w*APIView|RetrieveModelMixin/;
  for (const cls of pyClasses(file)) {
    if (!singleRecord.test(cls.bases) || !MONEY.test(`${file.path}\n${cls.name}\n${cls.body}`)) continue;
    if (/\bdef\s+get_queryset\b|request\.user|IsOwner|has_object_permission|check_object_permissions/.test(cls.body) || ADMIN_ONLY.test(cls.body)) continue;
    for (let n = cls.line + 1; n <= cls.endLine; n++) {
      const text = file.lines[n - 1]!;
      if (/^\s*queryset\s*=.*\.objects\.all\s*\(\s*\)/.test(text) && !isIgnored(file, n)) {
        out.push(hit(file, n, 'FX-OWN-001', 'critical', 'Money record read without an ownership check'));
      }
    }
  }
  return out;
}

export const pythonOwnershipRule: FileRule = {
  id: 'FX-OWN-001',
  pack: 'fintech',
  appliesTo: PYTHON,
  skipTests: true,
  run: (file) => [...ownershipInFunctions(file), ...ownershipInViewSets(file)],
};

/* ---------- FX-HOOK-001: a payment webhook that never verifies the provider's signature ---------- */

const PROVIDER = /paystack|flutterwave|monnify|interswitch|remita|opay|kora/i;
const SIGNATURE_CHECKED = /x-paystack-signature|HTTP_X_PAYSTACK_SIGNATURE|verif-hash|HTTP_VERIF_HASH|monnify-signature|HTTP_MONNIFY_SIGNATURE|compare_digest|hmac\.|verify_\w*signature|validate_\w*signature|is_valid_signature|verify_webhook|webhook\w*secret/i;

export const pythonWebhookRule: FileRule = {
  id: 'FX-HOOK-001',
  pack: 'fintech',
  appliesTo: PYTHON,
  skipTests: true,
  run(file) {
    if (!PROVIDER.test(file.text) || SIGNATURE_CHECKED.test(file.text)) return [];
    const out: Detection[] = [];
    for (const fn of pyFunctions(file)) {
      if (!isRequestHandler(fn)) continue;
      const isWebhook = /webhook/i.test(`${routePath(fn)} ${fn.name} ${fn.className ?? ''}`);
      if (!isWebhook || !(acceptsWrites(fn) || !fn.className)) continue;
      const line = fn.decorators.find((d) => /webhook/i.test(d.text))?.line ?? fn.line;
      if (!isIgnored(file, line)) out.push(hit(file, line, 'FX-HOOK-001', 'critical', 'Payment webhook without a signature check'));
    }
    return out;
  },
};

/* ---------- FX-TXN-001: read a balance, change it, write it back, with no lock ---------- */

const BALANCE_CHANGE = /\b[\w.]*balance\s*=\s*[\w.]*balance\s*[-+]|\b[\w.]*balance\s*[-+]=/i;
const WRITES_BACK = /\.save\s*\(|\.commit\s*\(|\.flush\s*\(|\.execute\s*\(/;
/** `transaction.atomic` alone isn't here: without a row lock, a read-then-write can still lose an update. */
const LOCKED = /select_for_update|with_for_update|for_update|FOR UPDATE|\bF\s*\(\s*["']\w*balance/i;

export const pythonBalanceRule: FileRule = {
  id: 'FX-TXN-001',
  pack: 'fintech',
  appliesTo: PYTHON,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    for (const fn of pyFunctions(file)) {
      if (!WRITES_BACK.test(fn.body) || LOCKED.test(fn.body)) continue;
      for (const { line, text } of bodyLines(file, fn)) {
        if (BALANCE_CHANGE.test(pyCodeOnly(text)) && !isIgnored(file, line)) {
          out.push(hit(file, line, 'FX-TXN-001', 'high', 'Balance update outside a transaction'));
        }
      }
    }
    return out;
  },
};

/* ---------- FX-PII-002 and FX-OTP-001: secrets of a customer in logs ---------- */

const LOG_CALL = /(?<![\w.])(?:print|(?:logging|\w*log(?:ger)?)\.(?:debug|info|warning|warn|error|exception|critical|log|msg))\s*\(/i;
const KYC_VALUE = /\b(?:bvn|nin|bvn_number|nin_number|bank_verification_number|national_id|national_id_number)\b/i;
const MASKED = /mask|redact|last4|last_four|\[\s*-4\s*:\s*\]|\*\*\*/i;
const OTP_VALUE = /\b(?:otp|otp_code|one_time_password|passcode|verification_code)\b/i;

/** `bool(c.bvn)`, `c.bvn is None` and `"set" if c.bvn else "missing"` say whether a value exists, not what it is. */
function withoutPresenceChecks(code: string): string {
  return code
    .replace(/\bbool\s*\([^)]*\)/g, ' ')
    .replace(/\blen\s*\([^)]*\)/g, ' ')
    .replace(/[\w.]+\s+is\s+(?:not\s+)?None\b/g, ' ')
    .replace(/\bif\s+(?:not\s+)?[\w.]+\s+else\b/g, ' ');
}

export const pythonKycLoggingRule: FileRule = {
  id: 'FX-PII-002',
  pack: 'fintech',
  appliesTo: PYTHON,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      const line = i + 1;
      if (!LOG_CALL.test(pyCodeOnly(text)) || isIgnored(file, line)) return;
      const code = withoutPresenceChecks(pyCodeOnly(pyStatementAt(file, line)));
      if (KYC_VALUE.test(code) && !MASKED.test(code)) out.push(hit(file, line, 'FX-PII-002', 'high', 'BVN or NIN written to logs'));
    });
    return out;
  },
};

const WEAK_RANDOM = /(?<![\w.])random\.(?:randint|randrange|choice|choices|random|sample|getrandbits)\s*\(/;
const CODE_WORD = /(?:^|[^a-z])(?:otp|pin|token|passcode|code|verification)(?:[^a-z]|$)/i;
const RESPONSE = /\b(?:return|JsonResponse|Response|jsonify)\b/;

export const pythonOtpRule: FileRule = {
  id: 'FX-OTP-001',
  pack: 'fintech',
  appliesTo: PYTHON,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    const functions = pyFunctions(file);
    file.lines.forEach((text, i) => {
      const line = i + 1;
      if (isIgnored(file, line)) return;
      const code = pyCodeOnly(text);
      if (WEAK_RANDOM.test(code)) {
        const fn = functions.find((f) => line >= f.bodyLine && line <= f.endLine);
        const near = file.lines.slice(Math.max(0, i - 1), i + 2).join('\n');
        if (CODE_WORD.test(`${near}\n${fn?.name ?? ''}`)) out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP generated with random'));
        return;
      }
      if (LOG_CALL.test(code)) {
        const stmt = pyStatementAt(file, line);
        const logged = pyCodeOnly(stmt);
        if (OTP_VALUE.test(logged) && !MASKED.test(logged)) out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP written to logs'));
        else if (/\botp\b[^\n]{0,20}?\b\d{4,8}\b/i.test(stmt)) out.push(hit(file, line, 'FX-OTP-001', 'medium', 'Hard-coded OTP in source'));
        return;
      }
      if (/^\s*\w*otp\w*\s*=\s*["']\d{4,8}["']/i.test(text)) {
        out.push(hit(file, line, 'FX-OTP-001', 'medium', 'Hard-coded OTP in source'));
        return;
      }
      if (RESPONSE.test(code)) {
        const stmt = pyStatementAt(file, line);
        if (/["']otp["']\s*:\s*[^\s"']|\bjsonify\s*\([^)]*\botp\s*=/i.test(stmt) && !MASKED.test(stmt)) {
          out.push(hit(file, line, 'FX-OTP-001', 'high', 'OTP returned in an API response'));
        }
      }
    });
    return out;
  },
};

/* ---------- FX-IDEM-001: a money-out route that a retry can replay ---------- */

const MONEY_OUT = /transfer|payout|withdraw|disburs|send[-_]?money/i;
const READ_ONLY_HELPER = /quote|fee|preview|estimate|validate|verify|lookup|name[-_]?enquiry|resolve/i;

export const pythonIdempotencyRule: FileRule = {
  id: 'FX-IDEM-001',
  pack: 'fintech',
  appliesTo: PYTHON,
  skipTests: true,
  run(file, ctx) {
    if (/idempoten/i.test(file.text)) return [];
    const out: Detection[] = [];
    for (const fn of pyFunctions(file)) {
      if (!isRequestHandler(fn) || !acceptsWrites(fn)) continue;
      const names = `${routePath(fn)} ${fn.name} ${fn.className ?? ''}`;
      if (!MONEY_OUT.test(names) || READ_ONLY_HELPER.test(names)) continue;
      const code = `${fn.decorators.map((d) => pyCodeOnly(d.text)).join('\n')}\n${pyCodeOnly(fn.signature)}\n${pyCodeOnly(fn.body)}`;
      const used = code.match(/[A-Za-z_]\w*/g) ?? [];
      if (used.some((n) => n !== fn.name && (/idempot|dedup|replay|paymentguard|withguard|payment_guard|with_guard/i.test(n) || ctx.idempotencyHelpers.has(n)))) continue;
      const line = fn.decorators.find((d) => MONEY_OUT.test(d.text))?.line ?? fn.line;
      if (!isIgnored(file, line)) out.push(hit(file, line, 'FX-IDEM-001', 'high', 'Transfer without an idempotency key'));
    }
    return out;
  },
};

export const PYTHON_FINTECH_RULES: FileRule[] = [pythonOwnershipRule, pythonWebhookRule, pythonBalanceRule, pythonKycLoggingRule, pythonOtpRule, pythonIdempotencyRule];
