import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { createProject } from '../src/analysis/project';
import { methodAt, reachableText } from '../src/analysis/other';
import { runScan } from '../src/scan';

/*
 * The account-takeover checks follow a login, OTP or reset handler into the services it calls, in Go, C#, PHP, Java
 * and Kotlin (#91), as they already do in JavaScript and Python. A limiter or expiry check in a service class in
 * another file now counts, and the same app without it still gets a finding.
 */

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
function repo(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'fortis-follow-'));
  dirs.push(dir);
  const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  g('init', '-q', '-b', 'main');
  g('config', 'user.email', 't@example.com');
  g('config', 'user.name', 'Test');
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), text);
  }
  g('add', '-A');
  g('commit', '-q', '-m', 'init');
  return dir;
}
const findings = async (files: Record<string, string>, ruleId: string) =>
  (await runScan({ root: repo(files), scope: 'full', packs: ['fintech'], offline: true })).detections.filter((d) => d.ruleId === ruleId).map((d) => `${d.file}:${d.line} ${d.title}`);

/** Each sample: a login route, a service it calls, and the service's limiter in a third file. `limited` false drops the limiter's check. */
type Sample = (limited: boolean) => Record<string, string>;

const SPRING: Sample = (limited) => ({
  'src/main/java/bank/web/AuthController.java': [
    'package bank.web;',
    '@RestController',
    'public class AuthController {',
    '  private final LoginService loginService;',
    '  public AuthController(LoginService loginService) { this.loginService = loginService; }',
    '  @PostMapping("/api/login")',
    '  public TokenResponse login(@RequestBody LoginRequest body) {',
    '    return loginService.authenticate(body);',
    '  }',
    '}',
  ].join('\n'),
  'src/main/java/bank/service/LoginService.java': [
    'package bank.service;',
    '@Service',
    'public class LoginService {',
    '  private final AttemptGuard guard;',
    '  public LoginService(AttemptGuard guard) { this.guard = guard; }',
    '  public TokenResponse authenticate(LoginRequest body) {',
    '    guard.check(body.getEmail());',
    '    return issue(body);',
    '  }',
    '}',
  ].join('\n'),
  'src/main/java/bank/service/AttemptGuard.java': [
    'package bank.service;',
    '@Component',
    'public class AttemptGuard {',
    '  private final Bucket bucket;',
    limited ? '  public void check(String key) { if (!bucket.tryConsume(1)) throw new TooManyRequestsException(); }' : '  public void check(String key) { audit.record(key); }',
    '}',
  ].join('\n'),
});

const ASPNET: Sample = (limited) => ({
  'Controllers/AuthController.cs': [
    '[ApiController]',
    '[Route("api/auth")]',
    'public class AuthController(IAuthService auth) : ControllerBase',
    '{',
    '    [HttpPost("login")]',
    '    public async Task<IActionResult> Login(LoginDto dto)',
    '    {',
    '        return Ok(await auth.SignInAsync(dto));',
    '    }',
    '}',
  ].join('\n'),
  'Services/AuthService.cs': [
    'public class AuthService : IAuthService',
    '{',
    '    private readonly ISignInGuard _guard;',
    '    public AuthService(ISignInGuard guard) { _guard = guard; }',
    '    public async Task<TokenDto> SignInAsync(LoginDto dto)',
    '    {',
    '        _guard.Hit(dto.Email);',
    '        return await IssueAsync(dto);',
    '    }',
    '}',
  ].join('\n'),
  'Services/SignInGuard.cs': [
    'public class SignInGuard : ISignInGuard',
    '{',
    limited ? '    public void Hit(string key) { if (_failedAttempts.Get(key) > 5) throw new LockedOutException(); }' : '    public void Hit(string key) { _log.LogInformation("sign-in"); }',
    '}',
  ].join('\n'),
});

const LARAVEL: Sample = (limited) => ({
  'routes/api.php': [
    '<?php',
    'use App\\Http\\Controllers\\AuthController;',
    "Route::post('login', [AuthController::class, 'login']);",
  ].join('\n'),
  'app/Http/Controllers/AuthController.php': [
    '<?php',
    'namespace App\\Http\\Controllers;',
    'class AuthController extends Controller',
    '{',
    '    public function __construct(private LoginService $logins) {}',
    '    public function login(Request $request)',
    '    {',
    '        return $this->logins->signIn($request->email, $request->password);',
    '    }',
    '}',
  ].join('\n'),
  'app/Services/LoginService.php': [
    '<?php',
    'namespace App\\Services;',
    'class LoginService',
    '{',
    '    public function __construct(private LoginGuard $guard) {}',
    '    public function signIn($email, $password) { $this->guard->check($email); return Auth::attempt(compact(\'email\', \'password\')); }',
    '}',
  ].join('\n'),
  'app/Services/LoginGuard.php': [
    '<?php',
    'namespace App\\Services;',
    'class LoginGuard',
    '{',
    limited ? "    public function check($key) { if (RateLimiter::tooManyAttempts('login:'.$key, 5)) { abort(429); } RateLimiter::hit('login:'.$key); }" : "    public function check($key) { Log::info('login', ['key' => $key]); }",
    '}',
  ].join('\n'),
});

const GO: Sample = (limited) => ({
  'cmd/api/routes.go': [
    'package main',
    'func routes(r *gin.Engine, h *handlers.AuthHandler) {',
    '\tr.POST("/api/login", h.Login)',
    '}',
  ].join('\n'),
  'internal/handlers/auth.go': [
    'package handlers',
    'type AuthHandler struct { svc *auth.Service }',
    'func (h *AuthHandler) Login(c *gin.Context) {',
    '\ttoken, err := h.svc.SignIn(c.PostForm("email"), c.PostForm("password"))',
    '\tif err != nil { c.JSON(401, nil); return }',
    '\tc.JSON(200, token)',
    '}',
  ].join('\n'),
  'internal/auth/service.go': [
    'package auth',
    'type Service struct { guard *Guard }',
    'func (s *Service) SignIn(email, password string) (string, error) {',
    '\tif err := s.guard.Allow(email); err != nil { return "", err }',
    '\treturn issue(email)',
    '}',
  ].join('\n'),
  'internal/auth/guard.go': [
    'package auth',
    'type Guard struct { limiter *rate.Limiter }',
    limited ? 'func (g *Guard) Allow(key string) error { if !g.limiter.Allow() { return ErrTooMany }; return nil }' : 'func (g *Guard) Allow(key string) error { return nil }',
  ].join('\n'),
});

const KOTLIN: Sample = (limited) => ({
  'src/main/kotlin/bank/AuthController.kt': [
    'package bank',
    '@RestController',
    'class AuthController(private val loginService: LoginService) {',
    '    @PostMapping("/api/login")',
    '    fun login(@RequestBody body: LoginRequest): TokenResponse {',
    '        return loginService.authenticate(body)',
    '    }',
    '}',
  ].join('\n'),
  'src/main/kotlin/bank/LoginService.kt': [
    'package bank',
    '@Service',
    'class LoginService(private val guard: AttemptGuard) {',
    '    fun authenticate(body: LoginRequest): TokenResponse {',
    '        guard.check(body.email)',
    '        return issue(body)',
    '    }',
    '}',
  ].join('\n'),
  'src/main/kotlin/bank/AttemptGuard.kt': [
    'package bank',
    '@Component',
    'class AttemptGuard {',
    limited ? '    fun check(key: String) { if (!bucket.tryConsume(1)) throw TooManyRequestsException() }' : '    fun check(key: String) { audit.record(key) }',
    '}',
  ].join('\n'),
});

describe('FX-RATE-001 follows a login handler into its services (the issue’s samples)', () => {
  it.each([
    ['Spring Boot', SPRING, 'src/main/java/bank/web/AuthController.java:6'],
    ['ASP.NET Core', ASPNET, 'Controllers/AuthController.cs:5'],
    ['Laravel', LARAVEL, 'routes/api.php:3'],
    ['Go (Gin)', GO, 'cmd/api/routes.go:3'],
    ['Kotlin (Spring)', KOTLIN, 'src/main/kotlin/bank/AuthController.kt:4'],
  ])('%s: no finding with the limiter in a separate service class, a finding without it', async (_, sample, where) => {
    expect(await findings(sample(true), 'FX-RATE-001')).toEqual([]);
    expect(await findings(sample(false), 'FX-RATE-001')).toEqual([`${where} Login without a rate limit`]);
  });
});

describe('FX-RESET-001 follows a reset handler into the token service', () => {
  const reset = (checksExpiry: boolean) => ({
    'src/main/java/bank/ResetController.java': [
      '@RestController',
      'public class ResetController {',
      '  private final ResetTokens tokens;',
      '  public ResetController(ResetTokens tokens) { this.tokens = tokens; }',
      '  @PostMapping("/api/password/reset")',
      '  public void resetPassword(@RequestBody ResetRequest request) {',
      '    User user = tokens.redeem(request.getToken());',
      '    user.setPassword(passwordEncoder.encode(request.getNewPassword()));',
      '  }',
      '}',
    ].join('\n'),
    'src/main/java/bank/ResetTokens.java': [
      '@Service',
      'public class ResetTokens {',
      '  public User redeem(String token) {',
      '    ResetToken t = repo.findByToken(token).orElseThrow();',
      checksExpiry ? '    if (t.getExpiresAt().isBefore(Instant.now())) throw new ExpiredException();' : '    log.debug("redeeming");',
      '    repo.delete(t);',
      '    return t.getUser();',
      '  }',
      '}',
    ].join('\n'),
  });

  it('accepts an expiry check in the service, and still reports one that is missing', async () => {
    expect(await findings(reset(true), 'FX-RESET-001')).toEqual([]);
    expect(await findings(reset(false), 'FX-RESET-001')).toEqual(['src/main/java/bank/ResetController.java:6 Password reset token accepted without an expiry check']);
  });
});

describe('the call model', () => {
  const project = (files: Record<string, string>) => {
    const sources = Object.fromEntries(Object.entries(files).map(([p, t]) => [p, { path: p, text: t, lines: t.split('\n') }]));
    return { p: createProject(Object.keys(files), (x) => sources[x] ?? null), sources };
  };

  it('goes through an interface to its implementations, even when the interface lives outside the scan', () => {
    const { p, sources } = project({
      'A.cs': 'public class A(IGuard guard) { public void Run() { guard.Check(); } }',
      'Guard.cs': 'public class Guard : IGuard { public void Check() { Throttle(); } }',
    });
    expect(reachableText(p, methodAt(p, sources['A.cs']!, 1, 'Run')!)).toContain('Throttle()');
  });

  it('stops at five calls deep and never loops', () => {
    const { p, sources } = project({
      'Loop.java': 'class Loop { void a() { b(); } void b() { a(); c(); } void c() { d(); } void d() { e(); } void e() { f(); } void f() { g(); } void g() { tooDeepLimiter(); } }',
    });
    const text = reachableText(p, methodAt(p, sources['Loop.java']!, 1, 'a')!);
    expect(text).toContain('void f()');
    expect(text).not.toContain('tooDeepLimiter');
  });

  it("leaves a call it can't resolve alone", () => {
    const { p, sources } = project({ 'H.go': 'package h\nfunc Login() { mystery().Allow() }\n' });
    expect(reachableText(p, methodAt(p, sources['H.go']!, 2, 'Login')!)).toBe('');
  });
});
