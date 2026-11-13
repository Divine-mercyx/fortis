import { describe, expect, it } from 'vitest';

import { AUTH_RULES, credentialKind, GLOBAL_LIMIT, rateLimitRule, resetRule, tokenRule, words } from '../src/rules/auth';
import { buildContext } from '../src/scan';
import { emptyContext, type FileRule, type SourceFile } from '../src/rules/types';

const file = (path: string, text: string): SourceFile => ({ path, text, lines: text.split('\n') });
const run = (rule: FileRule, path: string, text: string, ctx = emptyContext()) => rule.run(file(path, text), ctx);
const lines = (rule: FileRule, path: string, text: string) => run(rule, path, text).map((d) => d.line);
const titles = (rule: FileRule, path: string, text: string) => run(rule, path, text).map((d) => `${d.line}:${d.severity}:${d.title}`);

describe('words and credential routes', () => {
  it('splits names and paths the same way', () => {
    expect(words('verifyOtp')).toEqual(['verify', 'otp']);
    expect(words('/auth/verify-otp')).toEqual(['auth', 'verify', 'otp']);
    expect(words('reset_transaction_pin')).toEqual(['reset', 'transaction', 'pin']);
  });

  it('knows which routes someone can guess against', () => {
    expect(credentialKind('/auth/login', '')).toBe('Login');
    expect(credentialKind('/sign-in', '')).toBe('Login');
    expect(credentialKind('', 'signIn')).toBe('Login');
    expect(credentialKind('/oauth/token', '')).toBe('Login');
    expect(credentialKind('/otp/verify', '')).toBe('OTP check');
    expect(credentialKind('/2fa', '')).toBe('OTP check');
    expect(credentialKind('/wallet/pin/validate', '')).toBe('PIN check');
    expect(credentialKind('', 'verifyTransactionPin')).toBe('PIN check');
    expect(credentialKind('/password/forgot', '')).toBe('Password route');
    expect(credentialKind('/forgot', '')).toBe('Password reset');
  });

  it('leaves routes nobody guesses at alone', () => {
    expect(credentialKind('/auth/logout', '')).toBeNull();
    expect(credentialKind('/transfers', 'createTransfer')).toBeNull();
    expect(credentialKind('/shipping', 'updateShipping')).toBeNull();
    expect(credentialKind('/pin/policy', '')).toBeNull();
    expect(credentialKind('/opinion', 'postOpinion')).toBeNull();
  });
});

describe('FX-RATE-001: credential routes without a rate limit', () => {
  it('flags Express login, OTP and PIN routes with no limiter', () => {
    expect(titles(rateLimitRule, 'src/auth.ts', [
      "import { Router } from 'express';",
      'const router = Router();',
      "router.post('/auth/login', async (req, res) => { res.json(await login(req.body)); });",
      "router.post('/auth/verify-otp', async (req, res) => { res.json(await verify(req.body)); });",
      "router.post('/wallet/pin/verify', authenticate, verifyPin);",
      "router.get('/auth/login', (req, res) => res.render('login'));",
      "router.post('/auth/logout', (req, res) => res.json({}));",
    ].join('\n'))).toEqual([
      '3:high:Login without a rate limit',
      '4:high:OTP check without a rate limit',
      '5:high:PIN check without a rate limit',
    ]);
  });

  it('accepts a limiter on the route, in the handler, or across the app', () => {
    const limited = [
      "import rateLimit from 'express-rate-limit';",
      'const loginLimiter = rateLimit({ windowMs: 60_000, max: 5 });',
      "router.post('/auth/login', loginLimiter, async (req, res) => res.json({}));",
      "router.post('/otp/verify', async (req, res) => { if (await tooManyAttempts(req.ip)) return res.status(429).end(); res.json({}); });",
    ].join('\n');
    expect(lines(rateLimitRule, 'src/auth.ts', limited)).toEqual([]);
    expect(lines(rateLimitRule, 'src/auth.ts', "app.use('/api', apiLimiter);\nrouter.post('/auth/login', async (req, res) => res.json({}));")).toEqual([]);
    const ctx = buildContext([file('src/app.ts', "import { rateLimit } from 'express-rate-limit';\napp.use(rateLimit({ max: 100 }));")]);
    expect(ctx.rateLimitAll).toBe(true);
    expect(run(rateLimitRule, 'src/auth.ts', "router.post('/auth/login', async (req, res) => res.json({}));", ctx)).toEqual([]);
  });

  it('reads NestJS throttling on the method or the controller', () => {
    expect(lines(rateLimitRule, 'src/auth.controller.ts', [
      "@Controller('auth')",
      'export class AuthController {',
      "  @Post('login')",
      '  @Throttle({ default: { limit: 5, ttl: 60000 } })',
      '  login(@Body() body: LoginDto) { return this.auth.login(body); }',
      '',
      "  @Post('otp/verify')",
      '  verifyOtp(@Body() body: OtpDto) { return this.auth.verifyOtp(body); }',
      '}',
    ].join('\n'))).toEqual([7]);
    expect(lines(rateLimitRule, 'src/pin.controller.ts', [
      '@UseGuards(ThrottlerGuard)',
      "@Controller('pin')",
      'export class PinController {',
      "  @Post('verify')",
      '  verify(@Body() body: PinDto) { return this.pins.verify(body); }',
      '}',
    ].join('\n'))).toEqual([]);
  });

  it('flags Flask, FastAPI and Django routes, and accepts their limiters', () => {
    expect(titles(rateLimitRule, 'app/auth.py', [
      "@app.route('/login', methods=['POST'])",
      'def login():',
      '    return jsonify(do_login(request.json))',
      '',
      "@app.route('/otp/verify', methods=['POST'])",
      "@limiter.limit('5/minute')",
      'def verify_otp():',
      '    return jsonify(check(request.json))',
      '',
      '@router.post("/pin/verify")',
      'async def verify_pin(body: PinIn):',
      '    return await pins.verify(body)',
    ].join('\n'))).toEqual(['2:high:Login without a rate limit', '11:high:PIN check without a rate limit']);
    expect(lines(rateLimitRule, 'app/views.py', [
      'class LoginView(APIView):',
      '    throttle_classes = [AnonRateThrottle]',
      '    def post(self, request):',
      '        return Response(login(request.data))',
    ].join('\n'))).toEqual([]);
  });

  it('treats Django REST, slowapi, Flask-Limiter and django-axes settings as app-wide limits', () => {
    for (const text of [
      "REST_FRAMEWORK = {'DEFAULT_THROTTLE_CLASSES': ['rest_framework.throttling.AnonRateThrottle']}",
      'limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])',
      "MIDDLEWARE = ['axes.middleware.AxesMiddleware']",
      'app.add_middleware(SlowAPIMiddleware)',
      'await app.register(import("@fastify/rate-limit"), { max: 100 })',
      'providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }]',
    ]) expect(GLOBAL_LIMIT.test(text), text).toBe(true);
    expect(GLOBAL_LIMIT.test('await app.register(rateLimit, { global: false })')).toBe(false);
  });

  it('skips router mounts, staff actions and schema names, and names OTP sending', () => {
    expect(lines(rateLimitRule, 'src/app.ts', "app.use('/api/v1/auth/transaction-pin', pinRoutes);\napp.use('/api/v1/auth/login', loginRoutes);")).toEqual([]);
    expect(lines(rateLimitRule, 'src/staff.ts', "router.post('/customers/:id/send-password', isStaff, async (req, res) => res.json({}));")).toEqual([]);
    expect(lines(rateLimitRule, 'src/cards.ts', "router.post('/cards/charge', requireAuth, validateBody(chargeCardWithPinSchema), async (req, res) => res.json({}));")).toEqual([]);
    expect(titles(rateLimitRule, 'src/otp.ts', "router.post('/otp/send', async (req, res) => res.json({}));")).toEqual(['1:high:OTP sending without a rate limit']);
    expect(lines(rateLimitRule, 'src/pin.ts', "router.post('/pin/create', requireAuth, async (req, res) => res.json({}));")).toEqual([]);
  });

  it('finds a lockout in the service the route calls', async () => {
    const { createProject } = await import('../src/analysis/project');
    const routes = file('src/pin.routes.ts', "import { pinService } from './pin.service';\nrouter.post('/pin/verify', async (req, res) => res.json(await pinService.verify(req.body)));");
    const service = file('src/pin.service.ts', 'export const pinService = {\n  async verify(body) {\n    const row = await pins.get(body.userId);\n    if (row.attempts >= 5) throw new Error("locked");\n    return compare(body.pin, row.hash);\n  },\n};');
    const ctx = buildContext([routes, service]);
    ctx.project = createProject([routes.path, service.path], (p) => [routes, service].find((f) => f.path === p) ?? null);
    expect(rateLimitRule.run(routes, ctx)).toEqual([]);
    expect(rateLimitRule.run(routes, buildContext([routes])).map((d) => d.line)).toEqual([2]);
  });

  it('honours fortis-ignore and skips tests', () => {
    expect(lines(rateLimitRule, 'src/auth.ts', "// fortis-ignore-next-line\nrouter.post('/auth/login', async (req, res) => res.json({}));")).toEqual([]);
    expect(rateLimitRule.skipTests).toBe(true);
  });
});

describe('FX-JWT-001: weak tokens and sessions', () => {
  it('flags hard-coded secrets, fallbacks and tokens that never expire', () => {
    expect(titles(tokenRule, 'src/token.ts', [
      "import jwt from 'jsonwebtoken';",
      "const a = jwt.sign({ sub: user.id }, 'super-secret', { expiresIn: '15m' });",
      'const b = jwt.sign({ sub: user.id }, process.env.JWT_SECRET!);',
      "const secret = process.env.JWT_SECRET || 'dev-secret';",
      "const c = jwt.sign({ sub: user.id }, secret, { expiresIn: '1h' });",
    ].join('\n'))).toEqual([
      '2:high:JWT signed with a hard-coded secret',
      '3:medium:JWT issued without an expiry',
      '4:high:Signing secret falls back to a hard-coded value',
    ]);
  });

  it('flags signature and expiry checks that are off', () => {
    expect(titles(tokenRule, 'src/auth.ts', [
      "import jwt from 'jsonwebtoken';",
      'export function auth(req, res, next) {',
      "  const token = req.headers.authorization?.split(' ')[1];",
      '  const claims = jwt.decode(token);',
      '  next();',
      '}',
    ].join('\n'))).toEqual(["4:critical:JWT read with decode(), which skips the signature check"]);
    expect(titles(tokenRule, 'src/verify.ts', [
      "import jwt from 'jsonwebtoken';",
      "const claims = jwt.verify(token, key, { algorithms: ['none'] });",
      'const old = jwt.verify(token, key, { ignoreExpiration: true });',
      'const peek = jwt.decode(token);',
    ].join('\n'))).toEqual(['2:critical:JWT accepted without checking its signature', '3:high:JWT expiry not checked']);
  });

  it('reads PyJWT', () => {
    expect(titles(tokenRule, 'app/tokens.py', [
      'import jwt, os',
      'SECRET = os.getenv("JWT_SECRET", "changeme")',
      'def issue(user):',
      '    return jwt.encode({"sub": user.id}, SECRET, algorithm="HS256")',
      'def issue2(user):',
      '    payload = {"sub": user.id, "exp": datetime.utcnow() + timedelta(minutes=15)}',
      '    return jwt.encode(payload, SECRET, algorithm="HS256")',
      'def read(token):',
      '    return jwt.decode(token, options={"verify_signature": False})',
      'def read2(token):',
      '    return jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})',
      'def sign3(user):',
      '    return jwt.encode({"sub": user.id, "exp": 1}, "hardcoded-secret")',
    ].join('\n'))).toEqual([
      '2:high:Signing secret falls back to a hard-coded value',
      '4:medium:JWT issued without an expiry',
      '9:critical:JWT accepted without checking its signature',
      '11:high:JWT expiry not checked',
      '13:high:JWT signed with a hard-coded secret',
    ]);
  });

  it('flags hard-coded secrets in JWT and session config', () => {
    expect(titles(tokenRule, 'src/app.module.ts', [
      "JwtModule.register({ secret: 'nolt-jwt-secret', signOptions: { expiresIn: '15m' } }),",
      'JwtModule.register({ secret: process.env.JWT_SECRET, signOptions: { expiresIn: "15m" } }),',
    ].join('\n'))).toEqual(['1:high:JWT or session signed with a hard-coded secret']);
    expect(titles(tokenRule, 'src/server.js', [
      "const session = require('express-session');",
      "app.use(session({ secret: 'keyboard cat', resave: false,",
      '  cookie: { secure: false } }));',
    ].join('\n'))).toEqual(['2:high:JWT or session signed with a hard-coded secret', '3:medium:Session cookie sent over plain HTTP (secure off)']);
  });

  it('flags weak cookies and tokens in localStorage', () => {
    expect(titles(tokenRule, 'src/login.ts', [
      "res.cookie('access_token', token, { httpOnly: false, secure: true });",
      "res.cookie('refresh_token', token, { httpOnly: true, secure: false });",
      "res.cookie('theme', 'dark', { httpOnly: false });",
      "localStorage.setItem('accessToken', token);",
      "localStorage.setItem('theme', 'dark');",
    ].join('\n'))).toEqual([
      '1:medium:Session cookie readable by scripts (httpOnly off)',
      '2:medium:Session cookie sent over plain HTTP (secure off)',
      '4:medium:Access token stored in localStorage',
    ]);
    expect(titles(tokenRule, 'config/settings.py', 'SESSION_COOKIE_SECURE = False\nSESSION_COOKIE_HTTPONLY = False\nCSRF_COOKIE_SECURE = True')).toEqual([
      '1:medium:Session cookie sent over plain HTTP (secure off)',
      '2:medium:Session cookie readable by scripts (httpOnly off)',
    ]);
  });

  it('leaves safe code alone', () => {
    expect(lines(tokenRule, 'src/safe.ts', [
      "import jwt from 'jsonwebtoken';",
      'const secret = process.env.JWT_SECRET;',
      "if (!secret) throw new Error('JWT_SECRET is required');",
      "export const issue = (id: string) => jwt.sign({ sub: id }, secret, { expiresIn: '15m', algorithm: 'HS256' });",
      "export const check = (t: string) => jwt.verify(t, secret, { algorithms: ['HS256'] });",
      "res.cookie('session', id, { httpOnly: true, secure: true, sameSite: 'lax' });",
      '// jwt.sign({ a: 1 }, "commented-out")',
    ].join('\n'))).toEqual([]);
  });
});

describe('FX-RESET-001: password and PIN resets', () => {
  it('flags weak codes, leaked codes and Host-header links when asking for a reset', () => {
    expect(titles(resetRule, 'src/reset.ts', [
      "router.post('/password/forgot', async (req, res) => {",
      '  const user = await users.findByEmail(req.body.email);',
      '  const code = Math.floor(100000 + Math.random() * 900000);',
      "  const link = `https://${req.headers.host}/reset?code=${code}`;",
      '  logger.info({ code });',
      '  await mailer.send(user.email, link);',
      '  res.json({ ok: true, code });',
      '});',
    ].join('\n'))).toEqual([
      '3:high:Password reset code made with Math.random',
      '4:high:Password reset link built from the request\'s Host header',
      '5:high:Password reset token written to logs',
      '7:high:Password reset token returned in the API response',
    ]);
  });

  it('flags tokens that never expire or can be used twice', () => {
    expect(titles(resetRule, 'src/reset.ts', [
      "router.post('/password/reset', async (req, res) => {",
      '  const row = await resets.findOne({ token: req.body.token });',
      '  await users.update(row.userId, { password: await hash(req.body.newPassword) });',
      '  res.json({ ok: true });',
      '});',
    ].join('\n'))).toEqual(['1:medium:Password reset token accepted without an expiry check']);
    expect(titles(resetRule, 'src/reset.ts', [
      "router.post('/password/reset', async (req, res) => {",
      '  const row = await resets.findOne({ token: req.body.token });',
      '  if (row.expiresAt < new Date()) throw new Error("expired");',
      '  await users.update(row.userId, { password: await hash(req.body.newPassword) });',
      '  res.json({ ok: true });',
      '});',
    ].join('\n'))).toEqual(['1:medium:Password reset token can be used more than once']);
  });

  it('passes a careful reset flow', () => {
    expect(lines(resetRule, 'src/reset.ts', [
      "router.post('/password/forgot', async (req, res) => {",
      '  const user = await users.findByEmail(req.body.email);',
      "  if (user) await mailer.send(user.email, `${config.appUrl}/reset?token=${crypto.randomBytes(32).toString('hex')}`);",
      "  res.json({ message: 'If that account exists, we have sent a link.' });",
      '});',
      "router.post('/password/reset', async (req, res) => {",
      '  const row = await resets.findOne({ token: sha256(req.body.token) });',
      '  if (!row || row.expiresAt < new Date()) return res.status(400).end();',
      '  await users.update(row.userId, { password: await hash(req.body.newPassword) });',
      '  await resets.deleteMany({ userId: row.userId });',
      '  res.json({ ok: true });',
      '});',
    ].join('\n'))).toEqual([]);
  });

  it('flags account enumeration on the request step', () => {
    expect(titles(resetRule, 'src/forgot.ts', [
      "router.post('/password/forgot', async (req, res) => {",
      '  const user = await users.findByEmail(req.body.email);',
      "  if (!user) return res.status(404).json({ error: 'User not found' });",
      '  await mailer.sendResetEmail(user);',
      '  res.json({ ok: true });',
      '});',
    ].join('\n'))).toEqual(['3:low:Password reset says whether an account exists']);
  });

  it('reads Python and PIN resets', () => {
    expect(titles(resetRule, 'app/pin.py', [
      '@router.post("/pin/forgot")',
      'async def forgot_pin(body: ForgotPin, request: Request):',
      '    code = str(random.randint(1000, 9999))',
      '    link = f"{request.base_url}pin/reset?code={code}"',
      '    await sms.send(body.phone, code)',
      '    return {"sent": True, "code": code}',
    ].join('\n'))).toEqual([
      '3:high:PIN reset code made with random.randint',
      '4:high:PIN reset link built from the request\'s Host header',
      '6:high:PIN reset token returned in the API response',
    ]);
    expect(lines(resetRule, 'app/pin.py', [
      '@router.post("/pin/forgot")',
      'async def forgot_pin(body: ForgotPin):',
      '    code = f"{secrets.randbelow(10**6):06d}"',
      '    await sms.send(body.phone, code)',
      '    return {"sent": True}',
    ].join('\n'))).toEqual([]);
  });

  it('only reports enumeration where someone types in an email or phone', () => {
    expect(lines(resetRule, 'src/pin.service.ts', [
      'export const pins = {',
      '  async requestReset(customerId: number) {',
      '    const customer = await customers.findById(customerId);',
      "    if (!customer) throw badRequest('Account not found');",
      "    await sendEmail(customer.email, 'reset');",
      '  },',
      '};',
    ].join('\n'))).toEqual([]);
  });

  it('treats a function that makes the token as the request step, not the step that uses it', () => {
    expect(titles(resetRule, 'src/forgot.ts', [
      "router.post('/forgot-password', async (req, res) => {",
      '  const user = await db.query("SELECT * FROM customers WHERE LOWER(email) = $1", [req.body.email]);',
      "  if (!user) return res.status(404).json({ message: 'User not found' });",
      "  const token = randomBytes(32).toString('hex');",
      '  await db.query("UPDATE customers SET reset_password_token = $1 WHERE id = $2", [token, user.id]);',
      '  await sendMail(user.email, token);',
      '  res.json({ ok: true });',
      '});',
    ].join('\n'))).toEqual(['3:low:Password reset says whether an account exists']);
  });

  it('ignores functions that only reset something else', () => {
    expect(lines(resetRule, 'src/form.ts', 'export function resetForm(form) {\n  form.value = Math.random();\n  return { code: form.value };\n}')).toEqual([]);
  });
});

describe('the auth rules', () => {
  it('are fintech-pack rules for JavaScript, TypeScript and Python', () => {
    for (const r of AUTH_RULES) {
      expect(r.pack).toBe('fintech');
      for (const p of ['a.ts', 'a.js', 'a.tsx', 'a.mjs', 'a.py']) expect(r.appliesTo.test(p), `${r.id} ${p}`).toBe(true);
      expect(r.appliesTo.test('a.go')).toBe(false);
    }
  });
});

describe('staff dashboards and sign-in values that aren\'t credentials (the corpus findings of 2026-11-13)', () => {
  it('FX-RATE-001: a password reset in a staff dashboard is a staff action; a login there still counts', () => {
    const text = [
      'class PasswordResetView(SingleObjectMixin, FormView):',
      '    form_class = PasswordResetForm',
      '    http_method_names = ["post"]',
      '',
      '    def post(self, request, *args, **kwargs):',
      '        return super().post(request, *args, **kwargs)',
      '',
      'class StaffLoginView(APIView):',
      '    def post(self, request):',
      '        return Response(auth.login(request.data))',
    ].join('\n');
    expect(run(rateLimitRule, 'src/oscar/apps/dashboard/users/views.py', text).map((d) => d.line)).toEqual([9]);
    expect(run(rateLimitRule, 'src/oscar/apps/customer/views.py', text).map((d) => d.line)).toEqual([5, 9]);
  });

  it('FX-RATE-001: permission mixins and staff decorators make a view staff-only', () => {
    const text = [
      'class CustomerPasswordResetView(PermissionRequiredMixin, APIView):',
      '    permission_required = "accounts.change_customer"',
      '',
      '    def post(self, request, pk):',
      '        return Response(accounts.send_reset(pk))',
    ].join('\n');
    expect(run(rateLimitRule, 'accounts/views.py', text)).toEqual([]);
  });

  it('FX-JWT-001: an OAuth state, PKCE verifier or redirect under an auth key is not a token', () => {
    const text = [
      "localStorage.setItem('enablebanking_auth_state', state);",
      "sessionStorage.setItem('auth_code_verifier', verifier);",
      "localStorage.setItem('auth_redirect', path);",
      "localStorage.setItem('auth_token', token);",
    ].join('\n');
    expect(run(tokenRule, 'src/enablebanking.ts', text).map((d) => d.line)).toEqual([4]);
  });
});
