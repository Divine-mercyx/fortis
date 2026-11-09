import { PYTHON, pyCodeOnly, pyStatementAt } from './python';
import type { Detection, FileRule, SourceFile } from './types';
import { codeOnly, isIgnored, JS_TS, statementAt } from './types';

/*
 * Money-handling rules for JavaScript, TypeScript and Python, plus the schema files that define money
 * columns. Conservative, like the other fintech rules: each looks for one specific risky shape.
 * Silence a reviewed line with `// fortis-ignore` or `# fortis-ignore`.
 */

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
});

const SOURCE = /\.((c|m)?(j|t)sx?|py)$/i;
/** UI components format money for display. Nothing there stores it. */
const COMPONENT = /\.[jt]sx$/i;
/** Code that runs in the browser shows and collects money. Server-side code is what stores it. */
const BROWSER = /(^|\/)(wwwroot|public|static|assets|frontend|client|[\w-]+-client|dist|build)\//i;
/** Minified bundles: one huge line that matches everything and that nobody wrote. */
const tooLong = (text: string) => text.length > 500;
const isPython = (file: SourceFile) => PYTHON.test(file.path);
const code = (file: SourceFile, text: string) => (isPython(file) ? pyCodeOnly(text) : codeOnly(text));
const statement = (file: SourceFile, line: number) => (isPython(file) ? pyStatementAt(file, line) : statementAt(file, line));

const MONEY_CONTEXT = /transfer|wallet|account|payout|withdraw|deposit|transaction|payment|balance|loan|disburse|beneficiar|card|invoice|checkout|charge|order|paystack|flutterwave|monnify|stripe/i;

const MONEY_WORDS = new Set(['amount', 'amounts', 'balance', 'balances', 'price', 'prices', 'fee', 'fees', 'subtotal', 'total', 'principal', 'payout', 'naira', 'kobo', 'deposit', 'withdrawal']);

/** True when a name is about money: `totalAmount` and `unit_price`, but not `feedback` or `fees_page_url`. */
export function isMoneyName(name: string): boolean {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z]+/)
    .map((w) => w.toLowerCase());
  const last = words.filter(Boolean).at(-1);
  // The last word says what it is: `amount_label` and `fee_type` are not amounts.
  return last ? MONEY_WORDS.has(last) : false;
}

/* ---------- FX-MONEY-001: money as floating point ---------- */

const JS_PARSE = /\b(?:Number\.)?parseFloat\s*\(\s*([\w$.[\]'"?!]+)/;
const PY_PARSE = /(?<![\w.])float\s*\(\s*([\w.[\]'"]+)/;
const COLUMN_RULES: { applies: RegExp; re: RegExp }[] = [
  // Prisma: balance Float
  { applies: /\.prisma$/i, re: /^\s*(\w+)\s+Float\b/ },
  // SQL: balance FLOAT, amount DOUBLE PRECISION
  { applies: /\.sql$/i, re: /^\s*["`]?(\w+)["`]?\s+(?:FLOAT|REAL|DOUBLE)\b/i },
  // Django: balance = models.FloatField(), SQLAlchemy: balance = Column(Float)
  { applies: PYTHON, re: /^\s*(\w+)\s*(?::\s*\w+(?:\[[^\]]*\])?\s*)?=\s*(?:models\.FloatField|(?:db\.)?Column\s*\(\s*(?:db\.)?(?:Float|REAL)\b|mapped_column\s*\(\s*(?:Float|REAL)\b)/ },
  // Sequelize: balance: DataTypes.FLOAT, or balance: { type: DataTypes.DOUBLE }
  { applies: JS_TS, re: /^\s*(\w+)\s*:\s*(?:\{\s*type\s*:\s*)?(?:DataTypes|Sequelize)\.(?:FLOAT|DOUBLE|REAL)\b/ },
];
// TypeORM has the type on one line and the name on the next: @Column('float') then balance: number
const TYPEORM = /@Column\s*\(\s*(?:\{\s*type\s*:\s*)?["'`](?:float|double|real|double precision)["'`]/i;

export const moneyFloatRule: FileRule = {
  id: 'FX-MONEY-001',
  pack: 'fintech',
  appliesTo: /\.((c|m)?(j|t)sx?|py|prisma|sql)$/i,
  skipTests: true,
  run(file) {
    if (COMPONENT.test(file.path) || BROWSER.test(file.path)) return [];
    const out: Detection[] = [];
    const title = 'Money stored or computed as floating point';
    const columns = COLUMN_RULES.filter((r) => r.applies.test(file.path));
    file.lines.forEach((text, i) => {
      const line = i + 1;
      if (tooLong(text) || isIgnored(file, line)) return;
      for (const { re } of columns) {
        const name = re.exec(text)?.[1];
        if (name && isMoneyName(name)) {
          out.push(hit(file, line, 'FX-MONEY-001', 'high', title));
          return;
        }
      }
      if (TYPEORM.test(text)) {
        const name = /^\s*(?:(?:public|private|protected|readonly)\s+)*(\w+)[!?]?\s*:/.exec(file.lines[i + 1] ?? '')?.[1];
        if (name && isMoneyName(name)) out.push(hit(file, line, 'FX-MONEY-001', 'high', title));
        return;
      }
      if (!SOURCE.test(file.path)) return;
      const plain = code(file, text);
      // parseFloat(amount) < 0 only asks about the sign, and Math.round(parseFloat(amount) * 100) converts to kobo.
      if (/(?:parseFloat|float)\s*\([^()]*\)\s*(?:[<>]=?|[!=]==?)/.test(plain) || /(?:Math\.round|round|int)\s*\(\s*(?:Number\.)?(?:parseFloat|float)\s*\([^()]*\)\s*\*\s*100\b/.test(plain)) return;
      const match = (isPython(file) ? PY_PARSE : JS_PARSE).exec(plain);
      // The last part of the argument: parseFloat(req.body.amount), float(order.total).
      const arg = match?.[1]?.replace(/\W+$/, '').split(/\W+/).at(-1);
      // float(request.data["amount"]): the name is in a string, which code() blanks out.
      const key = match && isPython(file) ? /\[\s*["']([^"']+)["']\s*\]/.exec(text)?.[1] : undefined;
      if ((arg && isMoneyName(arg)) || (key && isMoneyName(key))) out.push(hit(file, line, 'FX-MONEY-001', 'medium', title));
    });
    return out;
  },
};

/* ---------- FX-PCI-001: card data in logs, analytics or plain-text storage ---------- */

const CARD_VALUE = /\b(?:cardNumber|card_number|cardNo|card_no|card\.number|card\.pan|cardPan|card_pan|cvv2?|cvc2?|cardCvv|card_cvv|cardExpiry|card_expiry|card\.expiry)\b/i;
// data["card_number"]: the name is in a string, which code() blanks out.
const CARD_KEY = /\[\s*["'](?:cardNumber|card_number|cardNo|card_no|cvv2?|cvc2?|cardCvv|card_cvv|cardExpiry|card_expiry)["']\s*\]/;
const MASKED = /mask|redact|last_?4|bin\b|slice\(\s*-4\s*\)|\[\s*-4\s*:\s*\]|\*\*\*|token/i;
const JS_LOG = /\b(console\.(log|info|warn|error|debug)|logger\.(log|info|warn|error|debug|trace)|log\.(info|warn|error|debug)|winston\.\w+|pino\.\w+)\s*\(/;
const PY_LOG = /\b(print|(?:logging|logger|log|_logger|LOGGER)\.(?:debug|info|warning|warn|error|exception|critical))\s*\(/;
const ANALYTICS = /\b(analytics|mixpanel|amplitude|segment|posthog|sentry|Sentry|ga|gtag|rudderanalytics)\.?\w*\.?(track|capture|identify|captureMessage|captureException|setExtra|setContext|logEvent|event)?\s*\(/;

/** `Boolean(card.cvv)` and `!!card.number` say whether it's there, not what it is. */
const withoutPresence = (text: string) =>
  text
    .replace(/\b(?:Boolean|bool|len)\s*\([^)]*\)/g, ' ')
    .replace(/!!\s*[\w.?]+/g, ' ')
    .replace(/[\w.?]+\s*(?:!==?|===?|is not|is)\s*(?:null|undefined|None)\b/g, ' ')
    .replace(/[\w.?]+\.length\b/g, ' ');

const CARD_COLUMNS: { applies: RegExp; re: RegExp }[] = [
  { applies: /\.prisma$/i, re: /^\s*(\w+)\s+String\b/ },
  { applies: /\.sql$/i, re: /^\s*["`]?(\w+)["`]?\s+(?:VARCHAR|CHAR|TEXT)\b/i },
  { applies: PYTHON, re: /^\s*(\w+)\s*(?::\s*\w+(?:\[[^\]]*\])?\s*)?=\s*(?:models\.(?:Char|Text)Field|(?:db\.)?Column\s*\(\s*(?:db\.)?(?:String|Text)\b|mapped_column\s*\(\s*(?:String|Text)\b)/ },
  { applies: JS_TS, re: /^\s*(\w+)\s*:\s*(?:\{\s*type\s*:\s*)?(?:String\b|DataTypes\.(?:STRING|TEXT)\b)/ },
];
// A CVV may never be kept at all, and a card number only encrypted, so a plain text column is the bug.
const CARD_COLUMN_NAME = /^(?:card_?number|card_?no|pan|card_?pan|cvv2?|cvc2?|card_?cvv|card_?cvc)$/i;

export const cardDataRule: FileRule = {
  id: 'FX-PCI-001',
  pack: 'fintech',
  appliesTo: /\.((c|m)?(j|t)sx?|py|prisma|sql)$/i,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    const columns = CARD_COLUMNS.filter((r) => r.applies.test(file.path));
    // A schema that mentions encryption is doing this properly.
    const encrypted = /encrypt|EncryptedCharField|EncryptedString|fernet|vault/i.test(file.text);
    file.lines.forEach((text, i) => {
      const line = i + 1;
      if (tooLong(text) || isIgnored(file, line)) return;
      for (const { re } of columns) {
        const name = re.exec(text)?.[1];
        if (name && CARD_COLUMN_NAME.test(name) && !encrypted && !MASKED.test(name)) {
          out.push(hit(file, line, 'FX-PCI-001', 'critical', 'Card data stored in plain text'));
          return;
        }
      }
      if (!SOURCE.test(file.path)) return;
      const python = isPython(file);
      const plain = code(file, text);
      const logged = (python ? PY_LOG : JS_LOG).test(plain);
      const tracked = ANALYTICS.test(plain);
      if (!logged && !tracked) return;
      const stmt = withoutPresence(code(file, statement(file, line)));
      if ((CARD_VALUE.test(stmt) || CARD_KEY.test(statement(file, line))) && !MASKED.test(stmt)) {
        out.push(hit(file, line, 'FX-PCI-001', 'critical', logged ? 'Card data written to logs' : 'Card data sent to analytics'));
      }
    });
    return out;
  },
};

/* ---------- FX-REF-001: predictable transaction references ---------- */

const REF_NAME = /(?:^|[^A-Za-z0-9_.])((?:[A-Za-z]+_)?(?:tx|txn|trans|transaction|payment|pay|transfer|payout|order|charge|merchant)?_?[Rr]ef(?:erence)?|[a-z]+(?:Ref|Reference))\s*(?::[^=\n]*?)?(?:=(?!=)|:)\s*(.+)$/;
const JS_WEAK = /\bMath\.random\s*\(|\bDate\.now\s*\(|new Date\s*\(\s*\)\s*\.getTime\s*\(|\+\s*new Date\s*\(/;
const PY_WEAK = /\brandom\.(?:random|randint|randrange|choice|choices|sample)\s*\(|\btime\.time(?:_ns)?\s*\(|\bdatetime\.(?:datetime\.)?(?:now|utcnow)\s*\(/;
// With real randomness in it, a timestamp is harmless.
const STRONG = /randomUUID|randomBytes|uuid|nanoid|ulid|cuid|secrets\.|token_hex|token_urlsafe/i;

export const predictableRefRule: FileRule = {
  id: 'FX-REF-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file) {
    if (COMPONENT.test(file.path) || !MONEY_CONTEXT.test(`${file.path}\n${file.text}`)) return [];
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      const line = i + 1;
      if (tooLong(text) || isIgnored(file, line)) return;
      const match = REF_NAME.exec(text);
      if (!match) return;
      const value = match[2]!;
      // Template literals and f-strings are where these get built, so look inside the text too.
      if ((isPython(file) ? PY_WEAK : JS_WEAK).test(value) && !STRONG.test(value)) {
        out.push(hit(file, line, 'FX-REF-001', 'high', 'Transaction reference built from a timestamp or weak random'));
      }
    });
    return out;
  },
};

/* ---------- FX-AMT-001: a charge amount trusted from the client ---------- */

const PROVIDER = /paystack|flutterwave|\bflw\b|stripe|monnify|korapay|\bkora\b|squad|seerbit|interswitch|remita|opay/i;
/** A call that starts a charge: paystack.transaction.initialize(, stripe.paymentIntents.create(, flw.Charge.card( */
const CHARGE_CALL = /(?:\b\w*(?:paystack|flutterwave|flw|stripe|monnify|korapay|kora|squad|seerbit|interswitch|remita|opay)\w*(?:\.\w+)*\.(?:initialize|initiate|create|charge|card|init|pay|checkout|Create)\w*\s*\()|(?:\.Charge\.\w+\s*\()/i;
const HTTP_CALL = /\b(?:axios|got|superagent|httpClient|requests|httpx)\.(?:post|request)\s*\(/;
const CHARGE_URL = /transaction\/initialize|\/charges?\b|\/payments\b|\/checkout/i;
const JS_FROM_REQUEST = /\bamount\s*:\s*[^,}\n]*\b(?:req|request|ctx\.request|ctx)\.(?:body|query)\b/;
const PY_FROM_REQUEST = /\bamount\s*[=:]\s*[^,)\n]*\brequest\.(?:data|json|POST|GET|form|args|get_json|query_params)\b|["']amount["']\s*:\s*[^,}\n]*\brequest\.(?:data|json|POST|GET|form|args|get_json|query_params)\b/;
const JS_TAKEN = /(?:\{[^}]*\bamount\b[^}]*\}\s*=\s*(?:req|request|ctx\.request)\.(?:body|query))|(?:\bamount\s*=\s*[^;\n]*\b(?:req|request|ctx\.request)\.(?:body|query)\b)/;
const PY_TAKEN = /^\s*amount\s*=\s*[^#\n]*\brequest\.(?:data|json|POST|GET|form|args|get_json|query_params)\b/;
const USES_AMOUNT = /(?:\bamount\s*[:=]\s*(?:amount\b|Math\.\w+\(\s*amount\b|Number\(\s*amount\b|int\(\s*amount\b|amount\s*\*))|(?:[{,]\s*amount\s*[,}])/;
/** Choosing how much to pay is the point of these. */
const USER_CHOOSES = /top-?_?up|fund(?:ing)?[-_ ]?wallet|wallet[-_ ]?fund|\bfund\b|deposit|donat|\btip\b|tips\b|contribut|pay[-_ ]?what|custom[-_ ]?amount|save|savings/i;

export const clientAmountRule: FileRule = {
  id: 'FX-AMT-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file) {
    if (COMPONENT.test(file.path) || !PROVIDER.test(file.text) || USER_CHOOSES.test(file.path)) return [];
    const python = isPython(file);
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      const line = i + 1;
      if (tooLong(text) || isIgnored(file, line) || !(CHARGE_CALL.test(text) || HTTP_CALL.test(text))) return;
      const stmt = statement(file, line);
      if (!CHARGE_CALL.test(text) && !CHARGE_URL.test(stmt)) return;
      // The nearby code says what this handler is for.
      const before = file.lines.slice(Math.max(0, i - 20), i).join('\n');
      if (USER_CHOOSES.test(`${before}\n${stmt}`)) return;
      const direct = (python ? PY_FROM_REQUEST : JS_FROM_REQUEST).test(stmt);
      const taken = before.split('\n').some((l) => (python ? PY_TAKEN : JS_TAKEN).test(l)) && USES_AMOUNT.test(code(file, stmt));
      if (direct || taken) out.push(hit(file, line, 'FX-AMT-001', 'critical', 'Charge amount taken from the request'));
    });
    return out;
  },
};

export const MONEY_RULES: FileRule[] = [moneyFloatRule, cardDataRule, predictableRefRule, clientAmountRule];
