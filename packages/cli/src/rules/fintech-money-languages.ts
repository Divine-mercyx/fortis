import { csCode } from './fintech-csharp';
import { jvmCode } from './fintech-jvm';
import { isMoneyName } from './fintech-money';
import { phpCode } from './fintech-php';
import type { Detection, FileRule, SourceFile } from './types';
import { codeOnly, isIgnored } from './types';

/*
 * The four money-handling rules for Java, Kotlin, C#, PHP and Go: floating-point money, card data
 * in logs or plain-text columns, predictable transaction references, and a charge amount taken from
 * the request. Same rule IDs as JavaScript, TypeScript and Python, so they share compliance mapping
 * and the dashboard. Line patterns, conservative like the other fintech rules: each looks for one
 * specific risky shape. Silence a reviewed line with `// fortis-ignore` (or `# fortis-ignore` in PHP).
 */

type Lang = 'java' | 'kt' | 'cs' | 'php' | 'go';
const LANGS = /\.(java|kt|cs|php|go)$/i;
const langOf = (file: SourceFile): Lang => /\.(java|kt|cs|php|go)$/i.exec(file.path)![1]!.toLowerCase() as Lang;

const code = (lang: Lang, text: string) => (lang === 'java' || lang === 'kt' ? jvmCode(text) : lang === 'cs' ? csCode(text) : lang === 'php' ? phpCode(text) : codeOnly(text));

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
});

/** Minified or generated lines: one huge line that matches everything and that nobody wrote. */
const tooLong = (text: string) => text.length > 500;
/** Front-end assets show and collect money; the server is what stores and charges it. */
const BROWSER = /(^|\/)(wwwroot|public|static|assets|resources\/js|frontend|client|dist|build)\//i;

/** Doc comments: ` * @param float $amount` describes a type, it doesn't use one. */
const DOC_LINE = /^\s*(?:\*|\/\*|\/\/)/;

const eachLine = (file: SourceFile, run: (text: string, line: number) => void) =>
  file.lines.forEach((text, i) => {
    if (!tooLong(text) && !DOC_LINE.test(text) && !isIgnored(file, i + 1)) run(text, i + 1);
  });

/** OpenAPI documentation classes describe the JSON an API takes; nothing is stored or computed in them. */
const API_DOCS = /(?:Swagger|ApiDocs?|OpenApi\w*Docs?)\.(?:java|kt|cs)$/i;

/** The statement starting on a line, as far as its brackets go. */
function statementAt(file: SourceFile, lang: Lang, line: number): string {
  let text = '';
  let depth = 0;
  for (let i = line - 1; i < Math.min(file.lines.length, line + 15); i++) {
    text += `${file.lines[i]}\n`;
    for (const ch of code(lang, file.lines[i]!)) {
      if ('({['.includes(ch)) depth++;
      else if (')}]'.includes(ch)) depth--;
    }
    if (depth <= 0) break;
  }
  return text;
}

/* ---------- FX-MONEY-001: money as floating point ---------- */

/** A declaration and the name it declares, per language: `private double amount`, `val balance: Double`, `Amount float64`. */
const FLOAT_DECLS: Record<Lang, RegExp[]> = {
  // Fields and locals end in ; or =. A parameter ends in , or ), and says how money is passed, not kept.
  java: [/\b(?:double|float|Double|Float)\s+(\w+)\s*(?:;|=(?!=))/g],
  kt: [/\bva[lr]\s+(\w+)\s*:\s*(?:Double|Float)\??(?=\s*[=,)]|\s*$)/g],
  cs: [/\b(?:public|private|protected|internal)\s+(?:(?:static|readonly|required|virtual|override)\s+)*(?:double|float|Double|Single)\??\s+(\w+)\s*(?:[;{]|=(?!=))/g, /^\s*(?:double|float)\??\s+(\w+)\s*=(?![=>])/g],
  // Typed properties: private float $balance
  php: [/\b(?:public|private|protected)\s+(?:(?:static|readonly)\s+)*\??float\s+\$(\w+)/g],
  // Struct fields: Balance float64 (a parameter list split over lines ends each one with a comma).
  go: [/^\s*([A-Za-z_]\w*)\s+\*?float(?:32|64)\b(?![^`\n]*,\s*$)(?!\s*[,)])/g],
};
/** Laravel migrations: $table->float('amount') */
const LARAVEL_FLOAT = /\$table->(?:float|double|unsignedFloat|unsignedDouble)\s*\(\s*['"](\w+)['"]/;
/** Turning a money value into a float: Double.parseDouble(amount), amount.toDouble(), double.Parse(amount), floatval($amount), strconv.ParseFloat(amount, 64). */
const FLOAT_PARSE: Record<Lang, RegExp> = {
  java: /\b(?:Double\.(?:parseDouble|valueOf)|Float\.(?:parseFloat|valueOf))\s*\(\s*([\w.()]+?)\s*\)/,
  kt: /([\w.()]+?)\s*\.\s*to(?:Double|Float)(?:OrNull)?\s*\(\s*\)/,
  cs: /\b(?:double|float|Double|Single)\.(?:Parse|TryParse)\s*\(\s*([\w.()]+?)\s*[,)]|\bConvert\.To(?:Double|Single)\s*\(\s*([\w.()]+?)\s*\)/,
  // Casts like (float) $x are PHP's everyday type juggling; floatval() is reading input as a float.
  php: /\b(?:floatval|doubleval)\s*\(\s*\$([\w>-]+)/,
  go: /\bstrconv\.ParseFloat\s*\(\s*([\w.()]+?)\s*,/,
};
/** The last part of an expression: request.getAmount() → amount, $order->total → total. */
const lastName = (expr: string | undefined) => {
  const parts = (expr ?? '').replace(/\(\s*\)/g, '').split(/->|\.|\W+/).filter(Boolean);
  const last = parts.at(-1) ?? '';
  return last.replace(/^get(?=[A-Z])/, '');
};

export const moneyFloatLanguagesRule: FileRule = {
  id: 'FX-MONEY-001',
  pack: 'fintech',
  appliesTo: LANGS,
  skipTests: true,
  run(file) {
    if (BROWSER.test(file.path) || API_DOCS.test(file.path)) return [];
    const lang = langOf(file);
    const out: Detection[] = [];
    const title = 'Money stored or computed as floating point';
    eachLine(file, (text, line) => {
      if (lang === 'php') {
        const column = LARAVEL_FLOAT.exec(text)?.[1];
        if (column && isMoneyName(column)) return void out.push(hit(file, line, 'FX-MONEY-001', 'high', title));
      }
      const plain = code(lang, text);
      for (const re of FLOAT_DECLS[lang]) {
        re.lastIndex = 0;
        for (const m of plain.matchAll(re)) {
          if (isMoneyName(m[1]!)) return void out.push(hit(file, line, 'FX-MONEY-001', 'high', title));
        }
      }
      // A sign check, and conversion to kobo, aren't keeping money as a float.
      if (/(?:[<>]=?|[!=]==?)\s*0(?:\.0)?\b/.test(plain) || /\*\s*100\b/.test(plain)) return;
      const parsed = FLOAT_PARSE[lang].exec(plain);
      if (parsed && isMoneyName(lastName(parsed[1] ?? parsed[2]))) out.push(hit(file, line, 'FX-MONEY-001', 'medium', title));
    });
    return out;
  },
};

/* ---------- FX-PCI-001: card data in logs or plain-text columns ---------- */

const CARD_VALUE = /\b(?:card_?(?:number|no|pan|cvv|cvc|expiry)|cvv2?|cvc2?)\b|\bcard\s*(?:\.|->)\s*(?:number|pan|cvv|cvc)\b|\bget(?:Card)?(?:Number|Pan|Cvv|Cvc)\s*\(/i;
/** $data['card_number'] and r.FormValue("cvv"): the name is in a string, which the code view blanks out. */
const CARD_KEY = /\[\s*['"](?:card_?number|card_?no|cvv2?|cvc2?|card_?cvv|card_?expiry)['"]\s*\]|\(\s*['"](?:card_?number|cvv2?|cvc2?)['"]\s*\)/i;
const MASKED = /mask|redact|last_?4|last_?four|\bbin\b|substr\(|substring\(|takeLast|TakeLast|\[\s*len\([^)]*\)\s*-\s*4|\*\*\*|token/i;
const LOG_CALL: Record<Lang, RegExp> = {
  java: /\b(?:log|logger|LOG|LOGGER)\s*\.\s*(?:trace|debug|info|warn|error)\s*\(|\bSystem\.(?:out|err)\.print(?:ln|f)?\s*\(/,
  kt: /\b(?:log|logger|LOG|LOGGER)\s*\.\s*(?:trace|debug|info|warn|error)\s*\(|^\s*println\s*\(/,
  cs: /\b_?(?:log|logger|Logger|Log)\s*\.\s*(?:Log\w*|Information|Debug|Warning|Error|Verbose|Fatal)\s*\(|\bConsole\.Write(?:Line)?\s*\(/,
  php: /\b(?:Log|Logger)::(?:\w+)\s*\(|\blogger\s*\(|\berror_log\s*\(|->\s*logger\s*->\s*\w+\s*\(|\b(?:var_dump|print_r|var_export)\s*\(/,
  go: /\b(?:log|logger|logrus|zap|slog|l)\s*\.\s*(?:Print\w*|Fatal\w*|Panic\w*|Info\w*|Debug\w*|Warn\w*|Error\w*|With\w*)\s*\(|\bfmt\.(?:Print|Fprint)\w*\s*\(/,
};
/** `card.getCvv() != null`, `isset($card['number'])` and `len(cardNumber)` say whether it's there, not what it is. */
const withoutPresence = (text: string) =>
  text
    .replace(/\b(?:isset|empty|strlen|len|count|string\.IsNullOrEmpty|String\.IsNullOrEmpty|isNullOrBlank|isNullOrEmpty)\s*\([^)]*\)/g, ' ')
    .replace(/[\w.$>()-]+\s*(?:!=|==|!==|===)\s*(?:null|nil|None)\b/g, ' ')
    .replace(/[\w.$>-]+\.(?:length|Length|isEmpty\(\)|isBlank\(\))/g, ' ');

const CARD_COLUMN = /^(?:card_?number|card_?no|pan|card_?pan|cvv2?|cvc2?|card_?cvv|card_?cvc)$/i;
/** Where an entity or table keeps a card field as plain text. */
const CARD_FIELDS: Record<Lang, { when: (file: SourceFile) => boolean; re: RegExp }> = {
  java: { when: (f) => /@Entity\b|@Table\b|@Document\b/.test(f.text), re: /^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:private|protected|public)?\s*String\s+(\w+)\s*[;=]/ },
  kt: { when: (f) => /@Entity\b|@Table\b|@Document\b/.test(f.text), re: /\bva[lr]\s+(\w+)\s*:\s*String\??/ },
  cs: { when: (f) => /\[Table\b|\[Key\]|DbSet<|(^|\/)(Entities|Domain)\//.test(f.text + f.path), re: /^\s*public\s+string\??\s+(\w+)\s*\{\s*get;/ },
  php: { when: (f) => /Schema::(?:create|table)\s*\(/.test(f.text), re: /\$table->(?:string|text|char|longText|mediumText)\s*\(\s*['"](\w+)['"]/ },
  go: { when: (f) => /`[^`]*\b(?:gorm|db|bson):"/.test(f.text), re: /^\s*(\w+)\s+\*?string\s+`[^`]*\b(?:gorm|db|bson):"/ },
};
/** A converter, an encrypted cast or a vault call is doing this properly. */
const ENCRYPTED = /encrypt|@Convert\b|Encrypted\w*|vault|tokeni[sz]|'encrypted'|=>\s*['"]encrypted/i;

export const cardDataLanguagesRule: FileRule = {
  id: 'FX-PCI-001',
  pack: 'fintech',
  appliesTo: LANGS,
  skipTests: true,
  run(file) {
    const lang = langOf(file);
    const out: Detection[] = [];
    const fields = CARD_FIELDS[lang];
    const storing = fields.when(file) && !ENCRYPTED.test(file.text);
    eachLine(file, (text, line) => {
      if (storing) {
        const name = fields.re.exec(text)?.[1];
        if (name && CARD_COLUMN.test(name)) return void out.push(hit(file, line, 'FX-PCI-001', 'critical', 'Card data stored in plain text'));
      }
      const plain = code(lang, text);
      if (!LOG_CALL[lang].test(plain)) return;
      const stmt = statementAt(file, lang, line);
      const inner = withoutPresence(code(lang, stmt));
      if ((CARD_VALUE.test(inner) || CARD_KEY.test(withoutPresence(stmt))) && !MASKED.test(stmt)) {
        out.push(hit(file, line, 'FX-PCI-001', 'critical', 'Card data written to logs'));
      }
    });
    return out;
  },
};

/* ---------- FX-REF-001: predictable transaction references ---------- */

const MONEY_CONTEXT = /transfer|wallet|account|payout|withdraw|deposit|transaction|payment|balance|loan|disburse|beneficiar|card|invoice|checkout|charge|order|paystack|flutterwave|monnify|stripe/i;
/** `reference =`, `val txRef: String =`, `$paymentReference =`, `ref :=`, `Reference = ` (C# initialisers, Go struct literals). */
const REF_ASSIGN = /(?<![\w.])\$?((?:[A-Za-z]+_?)?(?:[Rr]eference|[Rr]ef))\s*(?::\s*[\w?<>]+\s*)?(?::=|=(?![=>])|:(?!:))\s*(.+)$/;
/** `.reference(...)`, `setTxRef(...)`, `'reference' => ...` */
const REF_CALL = /(?:\.|\bset)((?:[A-Za-z]+_?)?(?:[Rr]eference|[Rr]ef))\s*\((.+)$|['"]((?:[a-z]+_)?(?:reference|ref|tx_ref|txref))['"]\s*(?:=>|:)\s*(.+)$/;
const NOT_A_REF = /^(?:href|xref|pref|coref|ref|Ref)$/;
const WEAK: Record<Lang, RegExp> = {
  java: /System\.(?:currentTimeMillis|nanoTime)\s*\(|new\s+Random\s*\(|Math\.random\s*\(|ThreadLocalRandom|(?:LocalDateTime|Instant|LocalDate|ZonedDateTime)\.now\s*\(|new\s+Date\s*\(\s*\)\.getTime/,
  kt: /System\.(?:currentTimeMillis|nanoTime)\s*\(|\bRandom\s*(?:\(|\.next)|Math\.random\s*\(|\.random\s*\(\s*\)|(?:LocalDateTime|Instant|LocalDate|ZonedDateTime)\.now\s*\(/,
  cs: /DateTime(?:Offset)?\.(?:Now|UtcNow)|\.Ticks\b|new\s+Random\s*\(|Random\.Shared|Environment\.TickCount/,
  php: /\b(?:time|microtime|rand|mt_rand|uniqid|date|hrtime)\s*\(|\bnow\s*\(\s*\)|Carbon::now/,
  go: /\btime\.Now\s*\(|\brand\.(?:Intn|Int31n|Int63n|Int|Int31|Int63|Uint32|Uint64|Float64|Perm|N)\s*\(/,
};
/** With real randomness in it, a timestamp is harmless. */
const STRONG = /randomUUID|UUID\.|SecureRandom|Guid\.NewGuid|RandomNumberGenerator|random_bytes|random_int|Str::(?:uuid|ulid|random|orderedUuid)|uuid\.New|ulid|nanoid|crypto\/rand|Uuid::|bin2hex|Ulid/i;

export const predictableRefLanguagesRule: FileRule = {
  id: 'FX-REF-001',
  pack: 'fintech',
  appliesTo: LANGS,
  skipTests: true,
  run(file) {
    if (!MONEY_CONTEXT.test(`${file.path}\n${file.text}`)) return [];
    const lang = langOf(file);
    // Go's crypto/rand has rand.Int too: only math/rand is weak.
    if (lang === 'go' && !/"math\/rand(?:\/v2)?"/.test(file.text) && !/time\.Now/.test(file.text)) return [];
    const goCrypto = lang === 'go' && /"crypto\/rand"/.test(file.text) && !/"math\/rand(?:\/v2)?"/.test(file.text);
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      const assign = REF_ASSIGN.exec(text);
      const call = REF_CALL.exec(text);
      const name = assign?.[1] ?? call?.[1] ?? call?.[3];
      const value = assign?.[2] ?? call?.[2] ?? call?.[4];
      if (!name || !value || NOT_A_REF.test(name.replace(/^\$/, ''))) return;
      // A comparison or lookup isn't building one.
      if (/^\s*=/.test(value)) return;
      const weak = WEAK[lang];
      const usesWeak = goCrypto ? /\btime\.Now\s*\(/.test(value) : weak.test(value);
      if (usesWeak && !STRONG.test(value)) out.push(hit(file, line, 'FX-REF-001', 'high', 'Transaction reference built from a timestamp or weak random'));
    });
    return out;
  },
};

/* ---------- FX-AMT-001: a charge amount trusted from the client ---------- */

const PROVIDER = /paystack|flutterwave|\bflw\b|stripe|monnify|korapay|\bkora\b|squad|seerbit|interswitch|remita|opay/i;
/** A call that starts a charge on a provider's SDK, or a request to its charge endpoint. */
const CHARGE_CALL = /\b\w*(?:paystack|flutterwave|flw|stripe|monnify|korapay|kora|squad|seerbit|interswitch|remita|opay)\w*(?:\s*(?:\.|->|::)\s*\w+(?:\(\s*\))?)*\s*(?:\.|->|::)\s*(?:initiali[sz]e|initiate|create|charge|card|init|pay|checkout)\w*\s*\(/i;
const CHARGE_URL = /transaction\/initiali[sz]e|\/charges?\b|\/v\d\/payments\b|\/checkout|\/merchant\/transactions\/init/i;
/** Handlers: where a request comes from the client. */
const IS_HANDLER: Record<Lang, RegExp> = {
  java: /@(?:Rest)?Controller\b|@(?:Post|Put|Request)Mapping\b/,
  kt: /@(?:Rest)?Controller\b|@(?:Post|Put|Request)Mapping\b|\bcall\.receive\b/,
  cs: /\bControllerBase\b|\[ApiController\]|\[FromBody\]|\bMapPost\s*\(/,
  php: /\bRequest\s+\$request\b|\$_POST\b|\brequest\s*\(\s*\)|\bFormRequest\b/,
  go: /http\.Request|\*gin\.Context|echo\.Context|\*fiber\.Ctx/,
};
/** The amount, straight from what the client sent. */
const FROM_REQUEST: Record<Lang, RegExp> = {
  java: /\b(?:request|req|body|dto|payload|form|input|command|cmd)\w*\s*\.\s*(?:getAmount\s*\(\s*\)|amount\b)/,
  kt: /\b(?:request|req|body|dto|payload|form|input|command|cmd)\w*\s*\.\s*amount\b|\bcall\.receive\b[^\n]*\.amount\b/,
  cs: /\b(?:request|req|body|dto|payload|model|input|command|cmd)\w*\s*\.\s*Amount\b/i,
  php: /\$request\s*->\s*(?:amount\b|input\s*\(\s*['"]amount['"]|get\s*\(\s*['"]amount['"]|post\s*\(\s*['"]amount['"])|\$request\s*\[\s*['"]amount['"]\s*\]|\$_POST\s*\[\s*['"]amount['"]\s*\]|\brequest\s*\(\s*['"]amount['"]|\$validated\s*\[\s*['"]amount['"]\s*\]|\$data\s*\[\s*['"]amount['"]\s*\]/,
  go: /\b(?:req|request|body|payload|input|in|dto|params)\s*\.\s*Amount\b|\.(?:FormValue|PostForm|Query)\s*\(\s*"amount"\s*\)/,
};
/** An assignment and the name it sets, per language. */
const ASSIGN: Record<Lang, RegExp> = {
  java: /(?:^|[\s(])(?:final\s+)?(?:[\w<>?,[\]]+\s+)?(\w+)\s*=(?!=)\s*(.+)$/,
  kt: /\bva[lr]\s+(\w+)\s*(?::[^=]+)?=(?!=)\s*(.+)$/,
  cs: /(?:^|[\s(])(?:[\w<>?,[\]]+\s+)?(\w+)\s*=(?![=>])\s*(.+)$/,
  php: /\$(\w+)\s*=(?![=>])\s*(.+)$/,
  go: /\b(\w+)(?:\s*,\s*\w+)*\s*(?::=|=(?!=))\s*(.+)$/,
};
/** Where a method or handler starts: the amount's trail doesn't cross into another one. */
const BOUNDARY = /^\s*(?:@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b|\[Http\w+|(?:public|private|protected|internal)\s[^=;]*\(|(?:override\s+)?fun\s|func\s|(?:(?:public|private|protected|static)\s+)*function\s)/;
const mentions = (lang: Lang, text: string, name: string) =>
  new RegExp(`(?<![\\w$.])\\$?${name}\\b`).test(lang === 'php' ? text : code(lang, text));

/** Choosing how much to pay is the point of these. */
const USER_CHOOSES = /top-?_?up|topup|fund(?:ing)?[-_ ]?wallet|wallet[-_ ]?fund|\bfund\b|deposit|donat|\btip\b|tips\b|contribut|pay[-_ ]?what|custom[-_ ]?amount|savings/i;

export const clientAmountLanguagesRule: FileRule = {
  id: 'FX-AMT-001',
  pack: 'fintech',
  appliesTo: LANGS,
  skipTests: true,
  run(file) {
    const lang = langOf(file);
    if (!PROVIDER.test(file.text) || !IS_HANDLER[lang].test(file.text) || USER_CHOOSES.test(file.path)) return [];
    const from = FROM_REQUEST[lang];
    const out: Detection[] = [];
    eachLine(file, (text, line) => {
      const plainLine = code(lang, text);
      if (!(CHARGE_CALL.test(plainLine) || CHARGE_URL.test(text))) return;
      const stmt = statementAt(file, lang, line);
      // Back to the start of this handler, at most 25 lines.
      let top = line - 1;
      while (top > 0 && line - top < 25 && !BOUNDARY.test(file.lines[top - 1]!)) top--;
      const before = file.lines.slice(Math.max(0, top - 1), line - 1);
      // The nearby code says what this handler is for.
      if (USER_CHOOSES.test(`${before.join('\n')}\n${stmt}`)) return;
      // Follow the client's amount through variables: amount = body.amount, payload = {amount}.
      const tainted: string[] = [];
      for (const l of before) {
        const m = ASSIGN[lang].exec(l);
        if (m && (from.test(m[2]!) || tainted.some((n) => mentions(lang, m[2]!, n)))) tainted.push(m[1]!);
      }
      if (from.test(stmt) || tainted.some((n) => mentions(lang, stmt, n))) out.push(hit(file, line, 'FX-AMT-001', 'critical', 'Charge amount taken from the request'));
    });
    return out;
  },
};

export const MONEY_LANGUAGE_RULES: FileRule[] = [moneyFloatLanguagesRule, cardDataLanguagesRule, predictableRefLanguagesRule, clientAmountLanguagesRule];
