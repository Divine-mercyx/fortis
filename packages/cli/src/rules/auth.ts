import { factsFor, type FileFacts, type FnFact, type RouteFact } from '../analysis/facts';
import { reachable } from './fintech';
import type { Detection, FileRule, ProjectContext, SourceFile } from './types';
import { isIgnored } from './types';

/*
 * Checks on how a service signs people in: rate limits on the routes an attacker can guess against,
 * how JWTs and session cookies are made and checked, and how password and PIN resets work. These are
 * the doors account takeovers come through, and fintech accounts are worth taking over.
 *
 * JavaScript, TypeScript and Python. The rate-limit and reset checks work on the route facts the
 * fintech rules use; the token checks read lines, because a JWT call looks the same in every framework.
 * Silence a reviewed line with `// fortis-ignore` or `# fortis-ignore`.
 */

const SOURCE = /\.(?:[cm]?[jt]sx?|py)$/i;
const PY = /\.py$/i;

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string, fix?: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
  ...(fix ? { fix } : {}),
});

/** Words of a name or path: `verifyOtp`, `/verify-otp` and `verify_otp` all give ['verify', 'otp']. */
export const words = (s: string) =>
  s.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

/** The text of a function, or of the function a route names when it isn't written in place. */
function handlerText(file: SourceFile, facts: FileFacts, route: RouteFact): { fn?: FnFact; text: string } {
  if (route.fn !== null) {
    const fn = facts.fns[route.fn]!;
    return { fn, text: [fn.source, ...fn.decorators.map((d) => d.text), classText(file, fn.owner)].join('\n') };
  }
  // `app.post('/pin/verify', auth, verifyPin)`: find verifyPin in this file.
  for (const ref of [...route.refs].reverse()) {
    const fn = facts.fns.find((f) => f.name === ref);
    if (fn) return { fn, text: [fn.source, ...fn.decorators.map((d) => d.text)].join('\n') };
  }
  return { text: '' };
}

/**
 * What applies to a whole class: the decorators above it (Nest's @Throttle, @UseGuards) and its own
 * attributes (Django REST's throttle_classes). Not its other methods: their decorators are their own.
 */
function classText(file: SourceFile, owner?: string): string {
  if (!owner) return '';
  const start = file.lines.findIndex((l) => new RegExp(`^\\s*(?:export\\s+)?(?:default\\s+)?class\\s+${owner}\\b`).test(l));
  if (start === -1) return '';
  const indent = /^\s*/.exec(file.lines[start]!)![0].length;
  const out = [file.lines[start]!];
  for (let i = start - 1; i >= 0 && /^\s*@/.test(file.lines[i]!); i--) out.unshift(file.lines[i]!);
  let member = -1;
  for (let i = start + 1; i < file.lines.length; i++) {
    const l = file.lines[i]!;
    if (!l.trim()) continue;
    const ind = /^\s*/.exec(l)![0].length;
    if (ind <= indent && !/^\s*[)}\]]/.test(l)) break;
    if (member === -1) member = ind;
    if (ind === member && /^\s*[A-Za-z_]\w*\s*(?::[^=(]*)?=(?!=|>)/.test(l)) out.push(l);
  }
  return out.join('\n');
}

/* ------------------------------------------------- FX-RATE-001: no rate limit */

/** What a rate limit, a throttle or a lockout looks like in the libraries teams use. */
export const LIMITED = /rate.?limit|ratelimit|limiter|throttl|slow.?down|brute|too.?many|lock.?out|locked|max.?attempts?|failed.?attempts?|login.?attempts?|attempts?.?(?:count|left|remaining)|\w*Attempts\b|\battempts\b|retry.?after|backoff|\baxes\b/i;

/** A limiter applied to the whole app or router, in this file or anywhere in the project. */
export const GLOBAL_LIMIT = new RegExp(
  [
    String.raw`\b(?:app|server|router|api|v1|instance)\s*\.\s*use\s*\(\s*(?:['"\`][^'"\`]*['"\`]\s*,\s*)?[\w.]*(?:rate.?limit|limiter|throttl|slow.?down)`,
    String.raw`\.register\s*\(\s*(?:await\s+)?(?:import\s*\(\s*['"]@fastify\/rate-limit|fastifyRateLimit|rateLimit)\b(?![^)]*global\s*:\s*false)`,
    String.raw`APP_GUARD[\s\S]{0,120}?ThrottlerGuard|useGlobalGuards\s*\([^)]*Throttl`,
    String.raw`DEFAULT_THROTTLE_CLASSES`,
    String.raw`\bLimiter\s*\([^)]*default_limits\s*=`,
    String.raw`SlowAPIMiddleware|AxesMiddleware|axes\.backends|['"]axes['"]|RatelimitMiddleware`,
    String.raw`\blimit_req\s+zone=`,
  ].join('|'),
  'i',
);

const CREDENTIAL: Record<string, string> = {
  login: 'Login', logon: 'Login', signin: 'Login', authenticate: 'Login', authentication: 'Login',
  otp: 'OTP check', totp: 'OTP check', passcode: 'OTP check', '2fa': 'OTP check', mfa: 'OTP check',
  pin: 'PIN check',
  password: 'Password route', passwd: 'Password route', forgot: 'Password reset',
};
/** Routes that only end a session, or only read settings, can't be brute-forced. */
const NOT_A_GUESS = new Set(['logout', 'signout', 'logoff', 'config', 'settings', 'policy', 'rules', 'status', 'options', 'methods', 'create', 'setup', 'set', 'enable', 'disable', 'exists', 'has']);
/** Sending an OTP isn't a guess, but unlimited sends run up SMS bills and flood the customer. */
const SENDS = new Set(['send', 'resend', 'request', 'generate', 'issue']);

/** What a route lets someone guess at, or null if nothing. */
export function credentialKind(path: string, names: string): string | null {
  const w = [...words(path), ...words(names)];
  if (w.some((x) => NOT_A_GUESS.has(x))) return null;
  // `sign in` and `log in` as two words.
  for (let i = 0; i + 1 < w.length; i++) if ((w[i] === 'sign' || w[i] === 'log') && w[i + 1] === 'in') return 'Login';
  if (w.includes('oauth') && w.includes('token')) return 'Login';
  if (w.includes('auth') && w.includes('token')) return 'Login';
  for (const x of w) {
    const kind = CREDENTIAL[x];
    if (!kind) continue;
    return kind === 'OTP check' && w.some((y) => SENDS.has(y)) ? 'OTP sending' : kind;
  }
  return null;
}

/** Decorators, mixins and guards that only let staff in. */
const STAFF_ONLY = /\b(?:staff_member_required|permission_required|PermissionRequiredMixin|UserPassesTestMixin|user_passes_test|IsAdminUser|admin_required|superuser_required)\b|@Roles\s*\(\s*['"](?:admin|staff)|Role\.(?:Admin|ADMIN|Staff|STAFF)\b/;
/** Folders that hold a staff dashboard or back office. */
const STAFF_AREA = /(?:^|\/)(?:dashboard|admin|backoffice|back-office|back_office)\//i;

const RATE_FIX = 'Limit attempts per account and per IP on this route: express-rate-limit or @nestjs/throttler in Node, slowapi or Flask-Limiter in Python, Django REST throttle_classes. Lock the account or PIN after a few failures, and answer every failure the same way.';

export const rateLimitRule: FileRule = {
  id: 'FX-RATE-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file, ctx: ProjectContext) {
    if (ctx.rateLimitAll || GLOBAL_LIMIT.test(file.text)) return [];
    if (!/log-?in|sign-?in|signIn|logIn|authenticat|otp|passcode|\bpin|Pin\b|password|passwd|2fa|mfa|forgot|token/i.test(file.text)) return [];
    const facts = factsFor(file);
    const out: Detection[] = [];
    for (const route of facts.routes) {
      if (!route.writes) continue;
      const { fn, text } = handlerText(file, facts, route);
      // Mounting a router (`app.use('/pin', pinRoutes)`) isn't a route: its own routes are checked where they're defined.
      if (/\.\s*use\s*\(/.test(file.lines[route.line - 1] ?? '')) continue;
      // Validation schemas and DTOs name the payload, not what the route does.
      const refs = route.refs.filter((r) => !/schema|dto|validat|serializer/i.test(r));
      const kind = credentialKind(route.path, `${fn?.name ?? ''} ${fn?.owner ?? ''} ${refs.join(' ')}`);
      if (!kind) continue;
      // Staff actions on a customer's account (send them a password, unlock a PIN) aren't guesses.
      if (route.refs.some((r) => /admin|staff|superuser|back-?office/i.test(r)) || /(?:^|\/)admin(?:\/|$)/i.test(route.path)) continue;
      if (STAFF_ONLY.test(text)) continue;
      // A password action in a staff dashboard (Django Oscar's dashboard, a back office) is staff acting on a customer.
      // Logins stay checked there: a staff login page is exactly what gets guessed at.
      if (/^Password/.test(kind) && STAFF_AREA.test(file.path)) continue;
      if (route.refs.some((r) => LIMITED.test(r)) || LIMITED.test(text)) continue;
      // A lockout can live in the service the handler calls.
      if (reachable(ctx, file, facts, route).sources.some((src) => LIMITED.test(src))) continue;
      if (isIgnored(file, route.line) || out.some((d) => d.line === route.line)) continue;
      out.push(hit(file, route.line, 'FX-RATE-001', 'high', `${kind} without a rate limit`, RATE_FIX));
    }
    return out;
  },
};

/* ------------------------------------------------- FX-JWT-001: weak tokens and sessions */

/** The text of a call that starts on line i, up to its closing parenthesis, at most 12 lines. */
function callText(file: SourceFile, i: number, from: number): string {
  let depth = 0;
  let out = '';
  for (let j = i; j < Math.min(file.lines.length, i + 12); j++) {
    const line = j === i ? file.lines[j]!.slice(from) : file.lines[j]!;
    for (const ch of line) {
      out += ch;
      if (ch === '(') depth++;
      else if (ch === ')' && --depth === 0) return out;
    }
    out += '\n';
  }
  return out;
}

const STR = String.raw`(?:'[^'\n]*'|"[^"\n]*"|\`[^\`$\n]*\`)`;
const TOKENISH = /token|jwt|session|auth|sid\b|access|refresh/i;

type Finding = { line: number; severity: Detection['severity']; title: string; fix: string };

const FIX = {
  secret: 'Read the signing secret from your secret store or an environment variable that must be set (fail at start-up if it is missing), make it at least 32 random bytes, and rotate it now: anyone with this repository can mint tokens for any user.',
  fallback: 'Drop the fallback. If the secret is missing, refuse to start, so a misconfigured server can never sign tokens with a value that is in the repository.',
  none: 'Always verify the signature, and pin the algorithm you sign with: jwt.verify(token, secret, { algorithms: ["HS256"] }) in Node, jwt.decode(token, key, algorithms=["HS256"]) in PyJWT. Never accept "none".',
  exp: 'Keep expiry checks on. A stolen token should stop working within minutes.',
  noExp: 'Give every access token a short life: expiresIn: "15m" in jsonwebtoken, an "exp" claim in PyJWT. Use refresh tokens, rotated on use, for longer sessions.',
  cookie: 'Set session and token cookies with httpOnly: true, secure: true and sameSite: "lax" or "strict" (SESSION_COOKIE_SECURE = True and SESSION_COOKIE_HTTPONLY = True in Django and Flask).',
  storage: 'Keep tokens out of localStorage, where any script on the page can read them: use an httpOnly, secure cookie, or memory plus a refresh cookie. In a mobile app use the Keychain or Keystore (expo-secure-store).',
};

/** Storage keys that name something about a sign-in, not the credential itself. */
const NOT_A_CREDENTIAL_KEY = /(?:state|nonce|verifier|challenge|redirect|return_?to|returnUrl|callback|provider|method|step|flow|mode|type|status|error|expir\w*|attempts?)$/i;

/** Every weak-token pattern in a file. Exposed for tests. */
export function tokenFindings(file: SourceFile): Finding[] {
  const out: Finding[] = [];
  const add = (line: number, severity: Detection['severity'], title: string, fix: string) => {
    if (!out.some((f) => f.line === line)) out.push({ line, severity, title, fix });
  };
  const py = PY.test(file.path);
  const verifiesSomewhere = /\bjwt\s*\.\s*verify\s*\(|\.verifyAsync\s*\(|\bjwtVerify\s*\(|passport-jwt|JwtStrategy|AuthGuard\s*\(\s*['"]jwt/.test(file.text);
  const readsBearer = /authorization|bearer/i.test(file.text);

  file.lines.forEach((raw, i) => {
    const line = raw.replace(py ? /\s+#.*$/ : /\s+\/\/.*$/, '');
    if (/^\s*(?:\/\/|#|\*)/.test(line)) return;
    const n = i + 1;

    // Signing calls: hard-coded secret, no expiry.
    const sign = /\bjwt\s*\.\s*(sign|encode)\s*\(/.exec(line) ?? /\b(sign)\s*\(\s*\{/.exec(/from\s+['"]jsonwebtoken['"]|require\(\s*['"]jsonwebtoken/.test(file.text) ? line : '');
    if (sign) {
      const call = callText(file, i, sign.index);
      const args = splitArgs(call.slice(call.indexOf('(') + 1, call.lastIndexOf(')')));
      const secret = args[1]?.trim() ?? '';
      if (new RegExp(`^${STR}$`).test(secret) && secret.length > 2) add(n, 'high', 'JWT signed with a hard-coded secret', FIX.secret);
      if (py) {
        // Only the function the call is in: an import of timedelta at the top says nothing about this token.
        let start = i;
        while (start > 0 && start > i - 25 && !/^\s*(?:async\s+)?def\s/.test(file.lines[start]!)) start--;
        const before = file.lines.slice(start, i + 1).join('\n') + call;
        if (sign[1] === 'encode' && !/['"]exp['"]|\bexp\s*=|timedelta|expires|expir/i.test(before)) add(n, 'medium', 'JWT issued without an expiry', FIX.noExp);
      } else if (sign[1] === 'sign' && !/expiresIn|\bexp\s*:|['"]exp['"]|expir/i.test(call)) {
        add(n, 'medium', 'JWT issued without an expiry', FIX.noExp);
      }
    }

    // Secrets in config objects: JwtModule.register({ secret: 'x' }), passport-jwt, express-session.
    const cfg = new RegExp(`\\b(secret|secretOrKey|secretOrPrivateKey|privateKey|jwtSecret|JWT_SECRET|SECRET_KEY|JWT_SECRET_KEY)\\s*[:=]\\s*(${STR})`).exec(line);
    if (cfg && cfg[2]!.length > 4 && !/process\.env|os\.environ|getenv|config\.|settings\./.test(line) && /jwt|session|passport|JwtModule|secretOrKey|JWT_SECRET|JWT_SECRET_KEY/i.test(file.text)) {
      if (/^(?:secretOrKey|secretOrPrivateKey|jwtSecret|JWT_SECRET|JWT_SECRET_KEY)$/.test(cfg[1]!) || /JwtModule|expressSession|session\s*\(|cookieSession|jwt/i.test(file.lines.slice(Math.max(0, i - 6), i + 1).join('\n'))) {
        add(n, 'high', 'JWT or session signed with a hard-coded secret', FIX.secret);
      }
    }

    // A fallback when the environment variable is missing.
    if (new RegExp(`(?:process\\.env\\.\\w*(?:JWT|TOKEN|SESSION|AUTH)\\w*|process\\.env\\[['"]\\w*(?:JWT|TOKEN|SESSION|AUTH)\\w*['"]\\])\\s*(?:\\|\\||\\?\\?)\\s*${STR}`, 'i').test(line) ||
        new RegExp(`(?:os\\.getenv|os\\.environ\\.get)\\(\\s*['"]\\w*(?:JWT|TOKEN|SESSION|AUTH|SECRET)\\w*['"]\\s*,\\s*${STR}`, 'i').test(line)) {
      add(n, 'high', 'Signing secret falls back to a hard-coded value', FIX.fallback);
    }

    // Signature or algorithm checks turned off.
    if (/algorithms?\s*[:=]\s*\[?\s*['"]none['"]/i.test(line) || /['"]verify_signature['"]\s*:\s*False/.test(line) || (/\bjwt\s*\.\s*decode\s*\(/.test(line) && /\bverify\s*=\s*False/.test(callText(file, i, line.indexOf('jwt'))))) {
      add(n, 'critical', 'JWT accepted without checking its signature', FIX.none);
    }
    if (!py && /\bjwt\s*\.\s*decode\s*\(/.test(line) && !verifiesSomewhere && readsBearer) {
      add(n, 'critical', 'JWT read with decode(), which skips the signature check', FIX.none);
    }
    if (/ignoreExpiration\s*:\s*true/.test(line) || /['"]verify_exp['"]\s*:\s*False/.test(line)) add(n, 'high', 'JWT expiry not checked', FIX.exp);

    // Cookies that scripts can read or that travel over HTTP.
    const cookieCall = /\b(?:res|response|reply|ctx)\s*\.\s*(?:cookie|setCookie|set_cookie|cookies\.set)\s*\(\s*(['"`])([^'"`]+)\1/.exec(line);
    if (cookieCall && TOKENISH.test(cookieCall[2]!)) {
      const call = callText(file, i, cookieCall.index);
      if (/httpOnly\s*:\s*false|httponly\s*=\s*False/.test(call)) add(n, 'medium', 'Session cookie readable by scripts (httpOnly off)', FIX.cookie);
      else if (/secure\s*:\s*false|secure\s*=\s*False/.test(call)) add(n, 'medium', 'Session cookie sent over plain HTTP (secure off)', FIX.cookie);
    }
    if (/^\s*(?:app\.config\[['"])?(?:SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|JWT_COOKIE_SECURE|CSRF_COOKIE_SECURE|REMEMBER_COOKIE_SECURE|REMEMBER_COOKIE_HTTPONLY)(?:['"]\])?\s*=\s*False\b/.test(line)) {
      add(n, 'medium', /HTTPONLY/.test(line) ? 'Session cookie readable by scripts (httpOnly off)' : 'Session cookie sent over plain HTTP (secure off)', FIX.cookie);
    }
    if (/\bcookie\s*:\s*\{[^}]*\b(?:httpOnly\s*:\s*false|secure\s*:\s*false)/.test(line) && /session/i.test(file.text)) {
      add(n, 'medium', /httpOnly\s*:\s*false/.test(line) ? 'Session cookie readable by scripts (httpOnly off)' : 'Session cookie sent over plain HTTP (secure off)', FIX.cookie);
    }

    // Tokens in localStorage.
    const ls = /\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(['"`])([^'"`]+)\1/.exec(line) ?? /\b(?:localStorage|sessionStorage)\s*\[\s*(['"`])([^'"`]+)\1\s*\]\s*=/.exec(line);
    // An OAuth `state`, a nonce or where to go next isn't a credential, even under an `auth_…` key.
    if (ls && /token|jwt|auth|session|bearer/i.test(ls[2]!) && !/csrf|theme|lang|locale/i.test(ls[2]!) && !NOT_A_CREDENTIAL_KEY.test(ls[2]!)) add(n, 'medium', 'Access token stored in localStorage', FIX.storage);
  });
  return out;
}

/** Top-level arguments of a call's argument list. */
function splitArgs(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote = '';
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (quote) {
      cur += ch;
      if (ch === '\\') { cur += s[++i] ?? ''; continue; }
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; cur += ch; continue; }
    if ('([{'.includes(ch)) depth++;
    if (')]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

export const tokenRule: FileRule = {
  id: 'FX-JWT-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file) {
    if (!/jwt|jsonwebtoken|jose|session|cookie|localStorage|sessionStorage|SECRET/i.test(file.text)) return [];
    return tokenFindings(file)
      .filter((f) => !isIgnored(file, f.line))
      .map((f) => hit(file, f.line, 'FX-JWT-001', f.severity, f.title, f.fix));
  },
};

/* ------------------------------------------------- FX-RESET-001: password and PIN resets */

const RESET_NAME = /reset|forgot|forgotten|recover|recovery/i;
const RESET_SUBJECT = /password|passwd|\bpin\b|Pin\b|passcode|credential|account|login/i;
const HOST_HEADER = /\breq(?:uest)?\s*\.\s*(?:headers\s*\.\s*host\b|headers\s*\[\s*['"]host['"]\s*\]|get\s*\(\s*['"]host['"]\s*\)|hostname\b|host\b)|request\.get_host\s*\(|request\.build_absolute_uri\s*\(|request\.url_root\b|request\.host_url\b|request\.base_url\b|request\.headers\.get\(\s*['"]host['"]/i;
const WEAK_TOKEN = /\bDate\.now\s*\(|\bnew Date\(\)\.getTime\s*\(|\buuid(?:\.v1|v1)\s*\(|\buuid\.uuid1\s*\(|\btime\.time\s*\(|\bMath\.random\s*\(|\brandom\.(?:randint|random|choice|choices|randrange)\s*\(/;
const SECRET_FIELD = /^(?:token|reset_?token|resetToken|code|reset_?code|resetCode|otp|pin|link|reset_?link|resetLink|url|reset_?url|resetUrl)$/i;
const NEW_SECRET = /new_?password|newPassword|new_?pin|newPin|password\s*[:=]|set_password|setPassword|\.password\s*=|hashPassword|hash_password|make_password|bcrypt|argon2/i;
/** The token or code comes in with the request: this function is the step that uses it. */
const TOKEN_FROM_REQUEST = /\b(?:body|params|query|data|json|form|POST|GET|args|payload|dto|input)\s*(?:\.|\[\s*['"])\s*(?:token|code|reset_?token|resetToken|reset_?code|resetCode|otp)\b|\{[^}]*\b(?:token|code|resetToken|resetCode|otp)\b[^}]*\}\s*=\s*(?:req|request|ctx|body|data|input|dto)\b|\b(?:token|code|otp)\s*:\s*\w+\s*[,)]|\bdef\s+\w+\s*\([^)]*\b(?:token|code)\b|\(\s*@(?:Body|Param|Query)\([^)]*\)\s*\w+|\bbody\s*:\s*\w+|=\s*(?:body|data|payload|dto)\.\w*(?:token|code)/i;
const CHECKS_EXPIRY = /expir|expires|ttl|valid_?until|validUntil|max_?age|maxAge|timedelta|minutes|issued_?at|issuedAt|created_?at|createdAt|isAfter|isBefore|\bgt\b|\$gt|>\s*(?:new Date|Date\.now|now|timezone\.now|datetime)/i;
const SINGLE_USE = /\.delete|delete\(|deleteOne|deleteMany|destroy|\.remove\(|invalidate|used_?at|usedAt|consumed|is_?used|isUsed|=\s*null|=\s*None|:\s*null|token\s*=\s*['"]{2}|redis\.del|\.del\(|unset/i;
const LOOKUP_BY_CONTACT = /find\w*By(?:Email|Phone|Username|Msisdn)|by_(?:email|phone|username)|where[^)\n]{0,60}\b(?:email|phone|username)|filter(?:_by)?\([^)\n]*\b(?:email|phone|username)|get\([^)\n]*\b(?:email|phone|username)\s*=|\(\s*\{\s*(?:email|phone|username)\b|(?:body|data|json|POST)[.\[]\s*['"]?(?:email|phone|username)/i;
const ENUMERATION = /(?:user|account|email)[^\n]{0,60}(?:not\s+found|does\s*n[o']?t\s+exist|not\s+exist|not\s+registered|unknown)|no\s+(?:user|account)\s+(?:found|with)|status\s*\(\s*404\s*\)|status_code\s*=\s*404|HTTP_404|NotFoundException|Http404|abort\s*\(\s*404/i;

export const RESET_FIX = {
  weak: 'Make reset codes and tokens with a cryptographic generator: crypto.randomBytes(32).toString("hex") or crypto.randomInt for numeric codes in Node, secrets.token_urlsafe(32) or secrets.randbelow in Python.',
  leak: 'Send the code or link only to the account\'s verified email or phone. Never return it in the response or write it to logs.',
  host: 'Build the reset link from a configured base URL (APP_URL), not from the request. A forged Host header otherwise sends the victim a link to the attacker\'s site, with a valid token in it.',
  expiry: 'Store when each token expires (15 to 60 minutes) and refuse it after that.',
  reuse: 'Delete or mark the token used as soon as the new password or PIN is set, and invalidate the account\'s other reset tokens and sessions.',
  enum: 'Answer the same way whether or not the account exists ("If that account exists, we\'ve sent a link"), so the reset form can\'t be used to find customers.',
};

/** Weak spots in a file's reset flows. Exposed for tests. */
export function resetFindings(file: SourceFile, facts: FileFacts): Finding[] {
  const out: Finding[] = [];
  const add = (line: number, severity: Detection['severity'], title: string, fix: string) => {
    if (!out.some((f) => f.line === line)) out.push({ line, severity, title, fix });
  };
  const routeOf = (fn: FnFact) => facts.routes.find((r) => r.fn === fn.id || r.refs.includes(fn.name));
  for (const fn of facts.fns) {
    const route = routeOf(fn);
    if (!fn.name && !route) continue;
    const label = `${fn.name} ${fn.owner ?? ''} ${route?.path ?? ''}`;
    if (!RESET_NAME.test(label)) continue;
    if (!RESET_SUBJECT.test(`${label}\n${fn.source}`)) continue;
    const kind = /\bpin\b|Pin\b|passcode/.test(`${label} ${fn.source}`) && !/password/i.test(label) ? 'PIN' : 'Password';

    for (const r of facts.randoms) {
      if (r.fn !== fn.id) continue;
      const api = /Math\.random|random\.\w+|Random\(\)|randint|rand\(/.exec(file.lines[r.line - 1] ?? '')?.[0] ?? r.api;
      add(r.line, 'high', `${kind} reset code made with ${api}`, RESET_FIX.weak);
    }
    // Timestamps and v1 UUIDs used as the token itself.
    fn.source.split('\n').forEach((l, k) => {
      if (/token|code|secret/i.test(l) && WEAK_TOKEN.test(l) && !/expir|expires|createdAt|created_at|issuedAt|ttl/i.test(l)) {
        add(fn.line + k, 'high', `${kind} reset token can be guessed`, RESET_FIX.weak);
      }
      if (HOST_HEADER.test(l)) add(fn.line + k, 'high', `${kind} reset link built from the request's Host header`, RESET_FIX.host);
    });
    for (const res of facts.responses) if (res.fn === fn.id && res.fields.some((f) => SECRET_FIELD.test(f))) add(res.line, 'high', `${kind} reset token returned in the API response`, RESET_FIX.leak);
    for (const log of facts.logs) if (log.fn === fn.id && log.values.some((v) => SECRET_FIELD.test(v) || /token|code|link/i.test(v))) add(log.line, 'high', `${kind} reset token written to logs`, RESET_FIX.leak);

    // Using a token: it has to expire, and it has to stop working once used.
    if (NEW_SECRET.test(fn.source) && TOKEN_FROM_REQUEST.test(fn.source) && !/randomBytes|randomInt|token_urlsafe|token_hex|randbelow|uuid4|randomUUID/.test(fn.source)) {
      if (!CHECKS_EXPIRY.test(fn.source)) add(fn.line, 'medium', `${kind} reset token accepted without an expiry check`, RESET_FIX.expiry);
      else if (!SINGLE_USE.test(fn.source)) add(fn.line, 'medium', `${kind} reset token can be used more than once`, RESET_FIX.reuse);
    } else if (/forgot|request|send|initiate|start/i.test(label) || /send(?:Mail|Email|Sms|SMS)|send_(?:mail|email|sms)|mailer|email/i.test(fn.source)) {
      // Asking for a reset: the answer mustn't say whether the account exists.
      // Only where someone outside types in an email or phone: a signed-in customer's own lookup can't enumerate.
      const m = LOOKUP_BY_CONTACT.test(fn.source) ? ENUMERATION.exec(fn.source) : null;
      if (m) add(fn.line + fn.source.slice(0, m.index).split('\n').length - 1, 'low', `${kind} reset says whether an account exists`, RESET_FIX.enum);
    }
  }
  return out.sort((a, b) => a.line - b.line);
}

export const resetRule: FileRule = {
  id: 'FX-RESET-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file) {
    if (!RESET_NAME.test(file.text)) return [];
    const facts = factsFor(file);
    return resetFindings(file, facts)
      .filter((f) => !isIgnored(file, f.line))
      .map((f) => hit(file, f.line, 'FX-RESET-001', f.severity, f.title, f.fix));
  },
};

export const AUTH_RULES: FileRule[] = [rateLimitRule, tokenRule, resetRule];
