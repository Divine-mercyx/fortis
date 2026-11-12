import type { Detection, FileRule, ProjectContext, SourceFile } from './types';
import { isIgnored } from './types';
import { credentialKind, LIMITED, RESET_FIX, words } from './auth';

/*
 * The account-takeover checks (FX-RATE-001, FX-JWT-001, FX-RESET-001) for Go, C#, PHP, Java and
 * Kotlin. Same rule IDs and the same reasoning as JavaScript and Python, on line patterns:
 *
 *   Go       net/http, chi, Gin, Echo, Fiber; golang-jwt
 *   C#       ASP.NET Core controllers and minimal APIs; Microsoft.IdentityModel / JwtBearer
 *   PHP      Laravel routes and controllers, Symfony attributes; firebase/php-jwt
 *   Java     Spring MVC; jjwt, auth0 java-jwt
 *   Kotlin   Spring MVC, Ktor; the same JWT libraries
 *
 * Silence a reviewed line with `// fortis-ignore` (or `# fortis-ignore` in PHP).
 */

type Lang = 'go' | 'cs' | 'php' | 'java' | 'kt';
const LANG_OF: [RegExp, Lang][] = [[/\.go$/i, 'go'], [/\.cs$/i, 'cs'], [/\.php$/i, 'php'], [/\.java$/i, 'java'], [/\.kts?$/i, 'kt']];
const langOf = (path: string): Lang | null => LANG_OF.find(([re]) => re.test(path))?.[1] ?? null;
export const OTHER_LANGUAGES = /\.(?:go|cs|php|java|kt|kts)$/i;

type Finding = { line: number; severity: Detection['severity']; title: string; fix: string };
const hit = (file: SourceFile, f: Finding, ruleId: string): Detection => ({
  ruleId,
  severity: f.severity,
  title: f.title,
  file: file.path,
  line: f.line,
  snippet: (file.lines[f.line - 1] ?? '').trim(),
  fix: f.fix,
});

/** A line without its trailing comment and with string contents kept: enough for these patterns. */
const stripComment = (line: string, lang: Lang) => line.replace(lang === 'php' ? /\s(?:\/\/|#)(?![^'"]*['"][^'"]*$).*$/ : /\s\/\/(?![^"]*"[^"]*$).*$/, '');
const isCommentLine = (line: string) => /^\s*(?:\/\/|#|\*|\/\*)/.test(line);

/* ------------------------------------------------- functions */

export type Fn = { name: string; start: number; end: number; text: string; route?: string };

const SIGNATURE: Record<Lang, RegExp> = {
  go: /^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(/,
  cs: /^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed)\s+)+[\w<>\[\],?. ]+\s+(\w+)\s*\(/,
  php: /^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+(\w+)\s*\(/,
  java: /^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)+[\w<>\[\],?. ]+\s+(\w+)\s*\(/,
  kt: /^\s*(?:(?:public|private|internal|protected|override|suspend|open|inline)\s+)*fun\s+(?:<[^>]+>\s*)?(\w+)\s*\(/,
};

/** Index of the brace that closes the first one at or after (line, col), skipping strings. */
function closeBrace(lines: string[], from: number): number {
  let depth = 0;
  let opened = false;
  for (let i = from; i < lines.length && i < from + 400; i++) {
    let quote = '';
    const l = lines[i]!;
    for (let k = 0; k < l.length; k++) {
      const ch = l[k]!;
      if (quote) {
        if (ch === '\\') k++;
        else if (ch === quote) quote = '';
        continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
      if (ch === '/' && l[k + 1] === '/') break;
      if (ch === '{') { depth++; opened = true; }
      else if (ch === '}' && --depth === 0 && opened) return i;
    }
    // A Kotlin expression body (`fun x() = ...`) has no braces: it ends on its own line.
    if (!opened && i > from && /=\s*\S/.test(lines[from]!) && !/\{\s*$/.test(lines[from]!)) return from;
  }
  return Math.min(lines.length - 1, from + 40);
}

/** Every function or method, with the route its annotations or attributes give it, if any. */
export function functionsOf(file: SourceFile, lang: Lang): Fn[] {
  const out: Fn[] = [];
  const lines = file.lines;
  for (let i = 0; i < lines.length; i++) {
    const m = SIGNATURE[lang].exec(lines[i]!);
    if (!m || /^\s*(?:if|for|while|switch|catch|return|new)\b/.test(lines[i]!)) continue;
    const end = closeBrace(lines, i);
    let route: string | undefined;
    // Annotations and attributes just above: @PostMapping("/login"), [HttpPost("login")], #[Route('/login')].
    for (let k = i - 1; k >= Math.max(0, i - 8); k--) {
      const r = /@(?:Post|Put|Patch|Request)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?(?:\[\s*)?["']([^"']*)["']|\[Http(?:Post|Put|Patch)\s*\(\s*"([^"]*)"|#\[Route\s*\(\s*['"]([^'"]+)['"][^\]]*methods:\s*\[[^\]]*['"]POST/i.exec(lines[k]!);
      if (r) { route = r[1] ?? r[2] ?? r[3] ?? ''; break; }
      if (/^\s*$/.test(lines[k]!) || /[;}]\s*$/.test(lines[k]!)) break;
    }
    out.push({ name: m[1]!, start: i + 1, end: end + 1, text: lines.slice(i, end + 1).join('\n'), ...(route !== undefined ? { route } : {}) });
  }
  return out;
}

/** The annotations or attributes directly above a method, nearest last. */
function annotationsAbove(file: SourceFile, fn: Fn): string[] {
  const out: string[] = [];
  for (let k = fn.start - 2; k >= 0 && k >= fn.start - 12; k--) {
    const l = file.lines[k]!;
    if (!/^\s*(?:@|\[|#\[)/.test(l) && !/^\s*\w+\s*=.*[,)]\s*$/.test(l)) break;
    out.unshift(l);
  }
  return out;
}

/** The line of the route annotation itself, where the finding belongs. */
function routeAnnotationLine(file: SourceFile, fn: Fn): number | null {
  for (let k = fn.start - 2; k >= 0 && k >= fn.start - 12; k--) {
    const l = file.lines[k]!;
    if (/Mapping\s*\(|\[Http(?:Post|Put|Patch)|#\[Route/.test(l)) return k + 1;
    if (!/^\s*(?:@|\[|#\[)/.test(l)) break;
  }
  return null;
}

/** The class an annotation-routed method is in: its prefix and its own attributes (rate limits, throttles). */
function classPrefix(file: SourceFile, fn: Fn): { prefix: string; attrs: string } {
  let attrs = '';
  let prefix = '';
  for (let i = fn.start - 2; i >= 0; i--) {
    const l = file.lines[i]!;
    if (/^\s*(?:public\s+|internal\s+|abstract\s+|open\s+|final\s+)*(?:class|object)\s+\w+/.test(l)) {
      for (let k = i - 1; k >= Math.max(0, i - 8); k--) {
        const a = file.lines[k]!;
        if (!/^\s*[@[#]/.test(a)) break;
        attrs += `${a}\n`;
        const p = /@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']*)["']|\[Route\s*\(\s*"([^"]*)"|#\[Route\s*\(\s*['"]([^'"]+)['"]/.exec(a);
        if (p) prefix = (p[1] ?? p[2] ?? p[3] ?? '').replace(/\[controller\]/i, '');
      }
      break;
    }
  }
  return { prefix, attrs };
}

/* ------------------------------------------------- routes */

type Route = { line: number; path: string; handler?: string; inline?: Fn; text: string };

/** Routes registered with a call (Go routers, minimal APIs, Laravel, Ktor), with their statement text. */
function registeredRoutes(file: SourceFile, lang: Lang): Route[] {
  const out: Route[] = [];
  const pattern =
    lang === 'go' ? /\.\s*(?:POST|Post|PUT|Put|PATCH|Patch|Handle|HandleFunc|Add|Any|Group\b)\s*\(\s*(?:"(?:POST|PUT|PATCH)"\s*,\s*)?["`]([^"`]+)["`]\s*,?\s*([^)]*)/
    : lang === 'cs' ? /\bMap(?:Post|Put|Patch)\s*\(\s*"([^"]+)"\s*,?\s*([^)]*)/
    : lang === 'php' ? /\bRoute::(?:post|put|patch|any|match)\s*\(\s*(?:\[[^\]]*\]\s*,\s*)?['"]([^'"]+)['"]\s*,?\s*([^;]*)/
    : lang === 'kt' ? /\b(?:post|put|patch)\s*\(\s*"([^"]+)"\s*\)\s*\{/
    : null;
  if (!pattern) return out;
  file.lines.forEach((raw, i) => {
    if (isCommentLine(raw)) return;
    const m = pattern.exec(stripComment(raw, lang));
    if (!m) return;
    // The whole statement, which may chain ->middleware(...) or ->RequireRateLimiting(...) on later lines.
    let text = stripComment(raw, lang);
    for (let k = i + 1; k < Math.min(file.lines.length, i + 6) && !/;\s*$|\)\s*$|\{\s*$/.test(text.trim()); k++) text += `\n${stripComment(file.lines[k]!, lang)}`;
    const handler = /(\w+)\s*\)?\s*$/.exec((m[2] ?? '').replace(/::class\s*,\s*['"](\w+)['"]\s*\]?/, ' $1').trim())?.[1];
    out.push({ line: i + 1, path: m[1]!, handler, text });
  });
  return out;
}

/** Inside a Laravel `Route::middleware('throttle:…')->group(function () { … })`, or a Go group with a limiter. */
function insideLimitedGroup(file: SourceFile, line: number): boolean {
  let depth = 0;
  for (let i = line - 2; i >= 0 && i > line - 200; i--) {
    const l = file.lines[i]!;
    depth += (l.match(/\}/g) ?? []).length - (l.match(/\{/g) ?? []).length;
    if (depth < 0) {
      if (LIMITED.test(l) || /throttle/i.test(l)) return true;
      depth = 0;
    }
  }
  return false;
}

/** Limits that cover the whole app, in these languages' frameworks. Feeds ProjectContext.rateLimitAll. */
export const GLOBAL_LIMIT_OTHER = new RegExp(
  [
    String.raw`\b(?:r|router|mux|e|app|api|engine|g)\s*\.\s*Use\s*\([^)]*(?:httprate|tollbooth|limiter|ratelimit|RateLimit|throttle)`,
    String.raw`\bapp\.UseRateLimiter\s*\(\s*\)[\s\S]{0,4000}GlobalLimiter|GlobalLimiter\s*=[\s\S]{0,4000}app\.UseRateLimiter`,
    String.raw`\bapp\.UseIpRateLimiting\s*\(|\bapp\.UseClientRateLimiting\s*\(`,
    String.raw`throttleApi\s*\(|['"]throttle:api['"]`,
    String.raw`Bucket4j\w*Filter|RateLimitFilter|FilterRegistrationBean<\s*\w*RateLimit`,
    String.raw`install\s*\(\s*RateLimit\s*\)[\s\S]{0,400}global\s*\{`,
  ].join('|'),
  'i',
);

const RATE_FIX = 'Limit attempts per account and per IP on this route, and lock the PIN or OTP after a few failures: httprate or tollbooth in Go, the ASP.NET Core rate limiter ([EnableRateLimiting]) in C#, the throttle middleware in Laravel, Bucket4j or resilience4j in Spring.';

export const otherRateLimitRule: FileRule = {
  id: 'FX-RATE-001',
  pack: 'fintech',
  appliesTo: OTHER_LANGUAGES,
  skipTests: true,
  run(file, ctx: ProjectContext) {
    const lang = langOf(file.path)!;
    if (ctx.rateLimitAll || GLOBAL_LIMIT_OTHER.test(file.text)) return [];
    if (!/log-?in|sign-?in|signIn|logIn|authenticat|otp|passcode|\bpin|Pin\b|password|passwd|2fa|mfa|forgot|token/i.test(file.text)) return [];
    const fns = functionsOf(file, lang);
    const out: Detection[] = [];
    const report = (line: number, kind: string) => {
      if (!isIgnored(file, line) && !out.some((d) => d.line === line)) out.push(hit(file, { line, severity: 'high', title: `${kind} without a rate limit`, fix: RATE_FIX }, 'FX-RATE-001'));
    };
    // Annotation-routed methods: Spring, ASP.NET controllers, Symfony.
    for (const fn of fns) {
      if (fn.route === undefined) continue;
      const { prefix, attrs } = classPrefix(file, fn);
      const kind = credentialKind(`${prefix}/${fn.route}`, fn.name);
      if (!kind) continue;
      const above = annotationsAbove(file, fn).join('\n');
      if (LIMITED.test(above) || LIMITED.test(attrs) || LIMITED.test(fn.text) || /EnableRateLimiting|RateLimiter\s*\(|@Throttle|Bucket|tryConsume/.test(`${above}\n${attrs}\n${fn.text}`)) continue;
      if (/\[DisableRateLimiting\]/.test(above)) { report(fn.start, kind); continue; }
      report(routeAnnotationLine(file, fn) ?? fn.start, kind);
    }
    // Registered routes: Go routers, minimal APIs, Laravel, Ktor.
    for (const route of registeredRoutes(file, lang)) {
      const handlerFn = route.handler ? fns.find((f) => f.name === route.handler) : undefined;
      const kind = credentialKind(route.path, route.handler ?? '');
      if (!kind || /^group$/i.test(route.handler ?? '')) continue;
      // The handler's own body when it's in this file; an inline closure; otherwise just the statement.
      const inline = /function\s*\(|func\s*\(|=>\s*\{|\)\s*\{\s*$/.test(route.text) ? file.lines.slice(route.line - 1, closeBrace(file.lines, route.line - 1) + 1).join('\n') : '';
      const body = handlerFn?.text ?? (inline || route.text);
      if (LIMITED.test(route.text) || /throttle|RequireRateLimiting/i.test(route.text) || LIMITED.test(body) || insideLimitedGroup(file, route.line)) continue;
      report(route.line, kind);
    }
    return out;
  },
};

/* ------------------------------------------------- FX-JWT-001 */

const JWT_FIX = {
  secret: 'Load the signing key from your secret store or an environment variable that must be set (refuse to start without it), make it at least 32 random bytes, and rotate it now: anyone with this repository can mint tokens.',
  fallback: 'Drop the default value. If the secret is missing, refuse to start, so a misconfigured server never signs with a value from the repository.',
  none: 'Always verify the signature with your key and a pinned algorithm. Never parse tokens unverified, and never accept "none".',
  exp: 'Keep lifetime validation on, so a stolen token stops working.',
  noExp: 'Give every access token a short expiry (15 minutes is common) and use rotating refresh tokens for longer sessions.',
  cookie: 'Mark session and token cookies HttpOnly and Secure, with SameSite=Lax or Strict.',
};

type JwtPattern = { re: RegExp; severity: Detection['severity']; title: string; fix: string; when?: RegExp };

const JWT: Record<Lang, JwtPattern[]> = {
  go: [
    { re: /\.ParseUnverified\s*\(|UnsafeAllowNoneSignatureType|SigningMethodNone/, severity: 'critical', title: 'JWT accepted without checking its signature', fix: JWT_FIX.none },
    { re: /\.SignedString\s*\(\s*\[\]byte\s*\(\s*"[^"]{3,}"\s*\)\s*\)|return\s+\[\]byte\s*\(\s*"[^"]{3,}"\s*\)\s*,\s*nil/, severity: 'high', title: 'JWT signed with a hard-coded secret', fix: JWT_FIX.secret, when: /jwt/ },
    { re: /\bjwt\.WithoutClaimsValidation\s*\(|SkipClaimsValidation\s*:\s*true/, severity: 'high', title: 'JWT expiry not checked', fix: JWT_FIX.exp },
    { re: /\bHttpOnly\s*:\s*false\b/, severity: 'medium', title: 'Session cookie readable by scripts (HttpOnly off)', fix: JWT_FIX.cookie, when: /http\.Cookie|SetCookie/ },
    { re: /\bSecure\s*:\s*false\b/, severity: 'medium', title: 'Session cookie sent over plain HTTP (Secure off)', fix: JWT_FIX.cookie, when: /http\.Cookie|SetCookie/ },
  ],
  cs: [
    { re: /SignatureValidator\s*=|RequireSignedTokens\s*=\s*false|ValidateIssuerSigningKey\s*=\s*false/, severity: 'critical', title: 'JWT accepted without checking its signature', fix: JWT_FIX.none },
    { re: /new\s+SymmetricSecurityKey\s*\(\s*Encoding\.\w+\.GetBytes\s*\(\s*"[^"]{3,}"\s*\)/, severity: 'high', title: 'JWT signed with a hard-coded secret', fix: JWT_FIX.secret },
    { re: /\["?Jwt:?\w*(?:Key|Secret)"?\]\s*\?\?\s*"[^"]+"|GetValue<string>\s*\(\s*"Jwt[^"]*"\s*\)\s*\?\?\s*"[^"]+"/, severity: 'high', title: 'Signing secret falls back to a hard-coded value', fix: JWT_FIX.fallback },
    { re: /ValidateLifetime\s*=\s*false|RequireExpirationTime\s*=\s*false/, severity: 'high', title: 'JWT expiry not checked', fix: JWT_FIX.exp },
    { re: /\bHttpOnly\s*=\s*false\b/, severity: 'medium', title: 'Session cookie readable by scripts (HttpOnly off)', fix: JWT_FIX.cookie },
    { re: /\bSecure\s*=\s*false\b|CookieSecurePolicy\.None/, severity: 'medium', title: 'Session cookie sent over plain HTTP (Secure off)', fix: JWT_FIX.cookie, when: /Cookie/ },
  ],
  php: [
    { re: /['"]alg['"]\s*=>\s*['"]none['"]|JWT::decode\s*\([^,)]+\)\s*;/i, severity: 'critical', title: 'JWT accepted without checking its signature', fix: JWT_FIX.none },
    { re: /JWT::encode\s*\((?:\s*\$\w+|[^;]*?\])\s*,\s*['"][^'"]{3,}['"]|new\s+Key\s*\(\s*['"][^'"]{3,}['"]/, severity: 'high', title: 'JWT signed with a hard-coded secret', fix: JWT_FIX.secret },
    { re: /\benv\s*\(\s*['"](?:JWT_SECRET|JWT_KEY|APP_KEY|SESSION_SECRET)['"]\s*,\s*['"][^'"]+['"]\s*\)|getenv\s*\(\s*['"]JWT_SECRET['"]\s*\)\s*\?:\s*['"]/, severity: 'high', title: 'Signing secret falls back to a hard-coded value', fix: JWT_FIX.fallback },
    { re: /['"]http_only['"]\s*=>\s*false|['"]httponly['"]\s*=>\s*false/i, severity: 'medium', title: 'Session cookie readable by scripts (HttpOnly off)', fix: JWT_FIX.cookie },
    { re: /^\s*['"]secure['"]\s*=>\s*false/, severity: 'medium', title: 'Session cookie sent over plain HTTP (Secure off)', fix: JWT_FIX.cookie, when: /cookie|session/i },
  ],
  java: [],
  kt: [],
};
JWT.java = [
  { re: /\.parseUnsecuredClaims\s*\(|\.parseClaimsJwt\s*\(|Jwts\.parser\(\)\s*\.parse\s*\(|\bJWT\.decode\s*\(/, severity: 'critical', title: 'JWT accepted without checking its signature', fix: JWT_FIX.none, when: /Authorization|Bearer|Filter|filter|token/ },
  { re: /Keys\.hmacShaKeyFor\s*\(\s*"[^"]{3,}"\.getBytes|\.signWith\s*\([^)]*"[^"]{3,}"|Algorithm\.HMAC(?:256|384|512)\s*\(\s*"[^"]{3,}"/, severity: 'high', title: 'JWT signed with a hard-coded secret', fix: JWT_FIX.secret },
  { re: /@Value\s*\(\s*"\\?\$\{[\w.-]*(?:jwt|secret|token)[\w.-]*:[^}]+\}"\s*\)/i, severity: 'high', title: 'Signing secret falls back to a hard-coded value', fix: JWT_FIX.fallback },
  { re: /(?:\.|\b)setHttpOnly\s*\(\s*false\s*\)|\.httpOnly\s*\(\s*false\s*\)|\bisHttpOnly\s*=\s*false\b/, severity: 'medium', title: 'Session cookie readable by scripts (HttpOnly off)', fix: JWT_FIX.cookie },
  { re: /(?:\.|\b)setSecure\s*\(\s*false\s*\)|\.secure\s*\(\s*false\s*\)|\b(?:secure|isSecure)\s*=\s*false\b/, severity: 'medium', title: 'Session cookie sent over plain HTTP (Secure off)', fix: JWT_FIX.cookie, when: /Cookie/ },
];
JWT.kt = JWT.java.map((p) => (p.title === 'JWT signed with a hard-coded secret' ? { ...p, re: /Keys\.hmacShaKeyFor\s*\(\s*"[^"]{3,}"\.(?:toByteArray|encodeToByteArray)|\.signWith\s*\([^)]*"[^"]{3,}"|Algorithm\.HMAC(?:256|384|512)\s*\(\s*"[^"]{3,}"/ } : p));

/** Tokens issued with no expiry: a builder or encode call with nothing about expiry nearby. */
function noExpiry(file: SourceFile, lang: Lang, fns: Fn[]): Finding[] {
  const out: Finding[] = [];
  const start = lang === 'go' ? /jwt\.NewWithClaims\s*\(/ : lang === 'cs' ? /new\s+JwtSecurityToken\s*\(|new\s+SecurityTokenDescriptor\b/ : lang === 'php' ? /JWT::encode\s*\(/ : /Jwts\.builder\s*\(\s*\)|JWT\.create\s*\(\s*\)/;
  const expiry = lang === 'go' ? /"exp"|ExpiresAt|NewNumericDate|time\.Now\(\)\.Add/ : lang === 'cs' ? /expires\s*:|Expires\s*=|AddMinutes|AddHours|AddDays/ : lang === 'php' ? /['"]exp['"]|expires|time\(\)\s*\+|addMinutes|addHours/ : /setExpiration|expiration\s*\(|withExpiresAt|expiresAt|plusMillis|plusSeconds|plusMinutes|plusHours/;
  file.lines.forEach((l, i) => {
    if (!start.test(l) || isCommentLine(l)) return;
    const fn = fns.find((f) => i + 1 >= f.start && i + 1 <= f.end);
    const scope = fn ? fn.text : file.lines.slice(Math.max(0, i - 15), i + 15).join('\n');
    if (!expiry.test(scope)) out.push({ line: i + 1, severity: 'medium', title: 'JWT issued without an expiry', fix: JWT_FIX.noExp });
  });
  return out;
}

export function otherTokenFindings(file: SourceFile): Finding[] {
  const lang = langOf(file.path);
  if (!lang) return [];
  const out: Finding[] = [];
  const add = (f: Finding) => { if (!out.some((x) => x.line === f.line)) out.push(f); };
  file.lines.forEach((raw, i) => {
    if (isCommentLine(raw)) return;
    const line = stripComment(raw, lang);
    for (const p of JWT[lang]) {
      if (p.re.test(line) && (!p.when || p.when.test(`${file.path}\n${file.text}`))) { add({ line: i + 1, severity: p.severity, title: p.title, fix: p.fix }); break; }
    }
    // Go: a fallback assigned when the variable is empty.
    if (lang === 'go' && /os\.Getenv\(\s*"\w*(?:JWT|SECRET|TOKEN|SESSION)\w*"\s*\)/.test(line)) {
      const v = /(\w+)\s*:?=\s*os\.Getenv/.exec(line)?.[1];
      const next = file.lines.slice(i + 1, i + 4).join('\n');
      if (v && new RegExp(`if\\s+${v}\\s*==\\s*""[\\s\\S]{0,40}?${v}\\s*=\\s*"[^"]+"`).test(next)) add({ line: i + 1, severity: 'high', title: 'Signing secret falls back to a hard-coded value', fix: JWT_FIX.fallback });
    }
  });
  for (const f of noExpiry(file, lang, functionsOf(file, lang))) add(f);
  return out.sort((a, b) => a.line - b.line);
}

export const otherTokenRule: FileRule = {
  id: 'FX-JWT-001',
  pack: 'fintech',
  appliesTo: OTHER_LANGUAGES,
  skipTests: true,
  run(file) {
    if (!/jwt|Jwt|JWT|Cookie|cookie|SymmetricSecurityKey|session/.test(`${file.path}\n${file.text}`)) return [];
    return otherTokenFindings(file).filter((f) => !isIgnored(file, f.line)).map((f) => hit(file, f, 'FX-JWT-001'));
  },
};

/* ------------------------------------------------- FX-RESET-001 */

const WEAK_RANDOM: Record<Lang, RegExp> = {
  go: /\brand\.(?:Intn|Int31n|Int63n|Int|Uint32|Perm)\s*\(/,
  cs: /new\s+Random\s*\(|Random\.Shared\.Next|DateTime\.(?:Now|UtcNow)\.Ticks/,
  php: /\b(?:rand|mt_rand|uniqid|lcg_value)\s*\(|\btime\s*\(\s*\)\s*\.|md5\s*\(\s*time\s*\(/,
  java: /new\s+Random\s*\(|Math\.random\s*\(|ThreadLocalRandom|System\.currentTimeMillis\s*\(\)/,
  kt: /\bRandom\.next\w*\s*\(|\(\d+\s*\.\.\s*\d+\)\.random\s*\(|Math\.random\s*\(|System\.currentTimeMillis\s*\(\)/,
};
/** `math/rand` in Go is only weak when that's the package imported, not crypto/rand. */
const goImportsMathRand = (text: string) => /["']math\/rand(?:\/v2)?["']/.test(text) && !/^\s*rand\s+["']crypto\/rand["']/m.test(text);

const HOST: Record<Lang, RegExp> = {
  go: /\br\.Host\b|\.Request\.Host\b|c\.Request\(\)\.Host\b|\.Hostname\(\)|r\.Header\.Get\(\s*"Host"\s*\)/,
  cs: /\bRequest\.Host\b|HttpContext\.Request\.Host\b|Request\.Scheme\s*\+/,
  php: /\$request->(?:getHost|root|getSchemeAndHttpHost|getHttpHost)\s*\(|\$_SERVER\[\s*['"](?:HTTP_HOST|SERVER_NAME)['"]\s*\]|request\(\)->(?:getHost|root)\s*\(/,
  java: /request\.(?:getServerName|getRequestURL|getHeader\(\s*"Host"\s*\))|ServletUriComponentsBuilder\.fromCurrent/,
  kt: /request\.(?:serverName|requestURL|getServerName|getRequestURL|getHeader\(\s*"Host"\s*\))|ServletUriComponentsBuilder\.fromCurrent|call\.request\.host\(\)|call\.request\.origin/,
};
const RESPONDS_SECRET: Record<Lang, RegExp> = {
  go: /(?:gin\.H|map\[string\]\w+|fiber\.Map|echo\.Map)\s*\{[^}]*"(?:token|code|otp|pin|reset_?token|link)"\s*:/i,
  cs: /(?:Ok|Json|Created)\s*\(\s*new\s*\{[^}]*\b(?:token|code|otp|resetToken|link)\b/i,
  php: /response\(\)->json\s*\(\s*\[[^\]]*['"](?:token|code|otp|reset_token|link)['"]\s*=>|return\s*\[[^\]]*['"](?:token|code|otp|reset_token)['"]\s*=>/i,
  java: /(?:ResponseEntity\.ok|Map\.of)\s*\([^;]*"(?:token|code|otp|resetToken|link)"/i,
  kt: /(?:mapOf|ResponseEntity\.ok)\s*\([^)]*"(?:token|code|otp|resetToken|link)"\s*(?:to|,)/i,
};
const LOGS_SECRET: Record<Lang, RegExp> = {
  go: /\b(?:log|logger|slog|zap|logrus)\.\w+\s*\([^)]*\b(?:token|code|otp|link)\b/i,
  cs: /\b_?log(?:ger)?\.Log\w*\s*\([^)]*\b(?:token|code|otp|link)\b/i,
  php: /\b(?:Log::\w+|logger\(\)->\w+|error_log)\s*\([^;]*\$(?:token|code|otp|link)\b/i,
  java: /\b(?:log|logger|LOG|LOGGER)\.\w+\s*\([^;]*\b(?:token|code|otp|link)\b/,
  kt: /\b(?:log|logger|LOG|LOGGER)\.\w+\s*\([^)]*\b(?:token|code|otp|link)\b/,
};
const NEW_SECRET = /new_?password|newPassword|NewPassword|new_?pin|newPin|NewPin|SetPassword|setPassword|set_password|\.Password\s*=|->password\s*=|Hash::make|bcrypt|password_hash|PasswordEncoder|passwordEncoder\.encode|HashPassword|GenerateFromPassword/;
const TOKEN_IN = /(?:Token|token|Code|code)\b[^\n]{0,40}(?:req|request|body|Body|dto|Dto|input|Input|params|form|Form|\$request|c\.(?:Query|Param|PostForm|Bind)|r\.FormValue)|(?:req|request|body|dto|input|\$request)[\w.\->()'"\[\]]{0,30}(?:token|code)/i;
const CHECKS_EXPIRY = /expir|Expir|ttl|TTL|valid_?until|ValidUntil|max_?age|MaxAge|isAfter|isBefore|After\(|Before\(|\bnow\b|Now\b|DateTime\.UtcNow|Carbon|addMinutes|created_?at|CreatedAt|issued_?at|IssuedAt/;
const SINGLE_USE = /\.Delete|\.delete|delete\(|Delete\(|->delete\s*\(|Remove\(|remove\(|destroy|invalidate|used_?at|UsedAt|consumed|IsUsed|isUsed|=\s*null|=\s*nil|=\s*None|->forceDelete|DeleteAsync|deleteBy/;
const LOOKUP_BY_CONTACT = /(?:Where|First|Find|Single|Any|filter|where|first|find)\w*\s*\([^)\n]*\b(?:Email|Phone|Username|email|phone|username)\b|(?:Email|email|Phone|phone|Username|username)\b[^\n]{0,40}(?:Where|where|find|Find|First|first|get|Get|By)|(?:findBy|FindBy|find_by|where)\w*\(?\s*['"]?(?:email|phone|username)/i;
const NOT_FOUND = /http\.StatusNotFound|StatusNotFound|NotFound\s*\(|abort\s*\(\s*404|HttpStatus\.NOT_FOUND|ResponseEntity\.notFound|status\(\s*404|UserNotFound|ModelNotFoundException|not\s+found|does\s*n[o']t\s+exist|not\s+registered/i;

export function otherResetFindings(file: SourceFile): Finding[] {
  const lang = langOf(file.path);
  if (!lang) return [];
  const out: Finding[] = [];
  const add = (f: Finding) => { if (!out.some((x) => x.line === f.line)) out.push(f); };
  const weakOk = lang !== 'go' || goImportsMathRand(file.text);
  const routes = registeredRoutes(file, lang);
  const fns = functionsOf(file, lang);
  // Laravel and Go closures registered on a reset route are functions too.
  for (const r of routes) if (/function\s*\(|func\s*\(/.test(r.text) && !fns.some((f) => f.start === r.line)) {
    const end = closeBrace(file.lines, r.line - 1);
    fns.push({ name: '', start: r.line, end: end + 1, text: file.lines.slice(r.line - 1, end + 1).join('\n'), route: r.path });
  }
  for (const fn of fns) {
    const label = `${fn.name} ${fn.route ?? ''} ${routes.find((r) => r.handler === fn.name)?.path ?? ''}`;
    if (!/reset|forgot|recover/i.test(words(label).join(' '))) continue;
    if (!/password|passwd|\bpin\b|Pin\b|passcode|credential|account|login/i.test(`${label}\n${fn.text}`)) continue;
    const kind = /\bpin\b|Pin\b|passcode/.test(`${label} ${fn.text}`) && !/password/i.test(label) ? 'PIN' : 'Password';
    fn.text.split('\n').forEach((l, k) => {
      if (isCommentLine(l)) return;
      const n = fn.start + k;
      if (weakOk && WEAK_RANDOM[lang].test(l)) add({ line: n, severity: 'high', title: `${kind} reset code can be guessed`, fix: RESET_FIX.weak });
      if (HOST[lang].test(l)) add({ line: n, severity: 'high', title: `${kind} reset link built from the request's Host header`, fix: RESET_FIX.host });
      if (RESPONDS_SECRET[lang].test(l)) add({ line: n, severity: 'high', title: `${kind} reset token returned in the API response`, fix: RESET_FIX.leak });
      if (LOGS_SECRET[lang].test(l)) add({ line: n, severity: 'high', title: `${kind} reset token written to logs`, fix: RESET_FIX.leak });
    });
    const consumes = NEW_SECRET.test(fn.text) && TOKEN_IN.test(fn.text) && !/RandomNumberGenerator|SecureRandom|random_bytes|crypto\/rand|Str::random|bin2hex|randomUUID|UUID\.randomUUID|Guid\.NewGuid/.test(fn.text);
    if (consumes) {
      if (!CHECKS_EXPIRY.test(fn.text)) add({ line: fn.start, severity: 'medium', title: `${kind} reset token accepted without an expiry check`, fix: RESET_FIX.expiry });
      else if (!SINGLE_USE.test(fn.text)) add({ line: fn.start, severity: 'medium', title: `${kind} reset token can be used more than once`, fix: RESET_FIX.reuse });
    } else if (LOOKUP_BY_CONTACT.test(fn.text)) {
      const lines = fn.text.split('\n');
      const k = lines.findIndex((l) => NOT_FOUND.test(l) && !isCommentLine(l));
      if (k !== -1) add({ line: fn.start + k, severity: 'low', title: `${kind} reset says whether an account exists`, fix: RESET_FIX.enum });
    }
  }
  return out.sort((a, b) => a.line - b.line);
}

export const otherResetRule: FileRule = {
  id: 'FX-RESET-001',
  pack: 'fintech',
  appliesTo: OTHER_LANGUAGES,
  skipTests: true,
  run(file) {
    if (!/reset|forgot|recover/i.test(file.text)) return [];
    return otherResetFindings(file).filter((f) => !isIgnored(file, f.line)).map((f) => hit(file, f, 'FX-RESET-001'));
  },
};

export const OTHER_AUTH_RULES: FileRule[] = [otherRateLimitRule, otherTokenRule, otherResetRule];
