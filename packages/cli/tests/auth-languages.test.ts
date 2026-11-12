import { describe, expect, it } from 'vitest';

import { functionsOf, GLOBAL_LIMIT_OTHER, otherRateLimitRule, otherResetRule, otherTokenRule } from '../src/rules/auth-languages';
import { buildContext } from '../src/scan';
import { emptyContext, type FileRule, type SourceFile } from '../src/rules/types';

const file = (path: string, text: string): SourceFile => ({ path, text, lines: text.split('\n') });
const titles = (rule: FileRule, path: string, text: string, ctx = emptyContext()) => rule.run(file(path, text), ctx).map((d) => `${d.line}:${d.severity}:${d.title}`);
const lines = (rule: FileRule, path: string, text: string, ctx = emptyContext()) => rule.run(file(path, text), ctx).map((d) => d.line);

describe('functions in each language', () => {
  it('finds methods and their route annotations', () => {
    const java = functionsOf(file('A.java', [
      '@RestController',
      '@RequestMapping("/api/auth")',
      'public class AuthController {',
      '    @PostMapping("/login")',
      '    public ResponseEntity<Token> login(@RequestBody LoginRequest body) {',
      '        return ResponseEntity.ok(auth.login(body));',
      '    }',
      '}',
    ].join('\n')), 'java');
    expect(java.map((f) => [f.name, f.start, f.end, f.route])).toEqual([['login', 5, 7, '/login']]);
    const cs = functionsOf(file('A.cs', '[HttpPost("verify-otp")]\npublic async Task<IActionResult> VerifyOtp([FromBody] OtpDto dto)\n{\n    return Ok(await _auth.VerifyOtp(dto));\n}'), 'cs');
    expect(cs.map((f) => [f.name, f.route])).toEqual([['VerifyOtp', 'verify-otp']]);
    const go = functionsOf(file('a.go', 'func (h *Handler) Login(c *gin.Context) {\n\tc.JSON(200, nil)\n}\n\nfunc helper() int {\n\treturn 1\n}'), 'go');
    expect(go.map((f) => [f.name, f.start, f.end])).toEqual([['Login', 1, 3], ['helper', 5, 7]]);
    const kt = functionsOf(file('A.kt', '@PostMapping("/pin/verify")\nfun verifyPin(@RequestBody body: PinRequest): PinResult {\n    return pins.verify(body)\n}\nfun short() = 1'), 'kt');
    expect(kt.map((f) => [f.name, f.route ?? null])).toEqual([['verifyPin', '/pin/verify'], ['short', null]]);
  });
});

describe('FX-RATE-001 in Go, C#, PHP, Java and Kotlin', () => {
  it('Go: flags credential routes with no limiter, and accepts limiters on the route or the router', () => {
    expect(titles(otherRateLimitRule, 'internal/http/routes.go', [
      'package http',
      'func Register(r *gin.Engine, h *Handler) {',
      '\tr.POST("/auth/login", h.Login)',
      '\tr.POST("/auth/otp/verify", h.VerifyOTP)',
      '\tr.POST("/wallet/pin/verify", limiter.Middleware(), h.VerifyPin)',
      '\tr.POST("/transfers", h.Transfer)',
      '\tr.GET("/auth/login", h.LoginPage)',
      '}',
    ].join('\n'))).toEqual(['3:high:Login without a rate limit', '4:high:OTP check without a rate limit']);
    expect(lines(otherRateLimitRule, 'cmd/api/main.go', 'r := chi.NewRouter()\nr.Use(httprate.LimitByIP(100, time.Minute))\nr.Post("/login", h.Login)')).toEqual([]);
  });

  it('C#: controllers and minimal APIs, with [EnableRateLimiting] and RequireRateLimiting', () => {
    expect(titles(otherRateLimitRule, 'Controllers/AuthController.cs', [
      '[ApiController]',
      '[Route("api/auth")]',
      'public class AuthController : ControllerBase',
      '{',
      '    [HttpPost("login")]',
      '    [EnableRateLimiting("login")]',
      '    public async Task<IActionResult> Login([FromBody] LoginDto dto)',
      '    {',
      '        return Ok(await _auth.Login(dto));',
      '    }',
      '',
      '    [HttpPost("pin/verify")]',
      '    public async Task<IActionResult> VerifyPin([FromBody] PinDto dto)',
      '    {',
      '        return Ok(await _pins.Verify(dto));',
      '    }',
      '}',
    ].join('\n'))).toEqual(['12:high:PIN check without a rate limit']);
    expect(titles(otherRateLimitRule, 'Program.cs', [
      'app.MapPost("/auth/otp/verify", (OtpDto dto, IAuth auth) => auth.VerifyOtp(dto));',
      'app.MapPost("/auth/login", (LoginDto dto, IAuth auth) => auth.Login(dto)).RequireRateLimiting("login");',
    ].join('\n'))).toEqual(['1:high:OTP check without a rate limit']);
  });

  it('PHP: Laravel routes, throttle middleware and throttled groups', () => {
    expect(titles(otherRateLimitRule, 'routes/api.php', [
      '<?php',
      "Route::post('/login', [AuthController::class, 'login']);",
      "Route::post('/otp/verify', [OtpController::class, 'verify'])->middleware('throttle:5,1');",
      "Route::middleware(['throttle:pin'])->group(function () {",
      "    Route::post('/pin/verify', [PinController::class, 'verify']);",
      '});',
      "Route::post('/transfers', [TransferController::class, 'store']);",
    ].join('\n'))).toEqual(['2:high:Login without a rate limit']);
    expect(GLOBAL_LIMIT_OTHER.test("->withMiddleware(function (Middleware $middleware) { $middleware->throttleApi(); })")).toBe(true);
  });

  it('Java and Kotlin: Spring mappings, with Bucket4j, resilience4j or a lockout in the method', () => {
    expect(titles(otherRateLimitRule, 'src/main/java/ng/nolt/AuthController.java', [
      '@RestController',
      '@RequestMapping("/api/auth")',
      'public class AuthController {',
      '    @PostMapping("/login")',
      '    public Token login(@RequestBody LoginRequest body) {',
      '        return auth.login(body);',
      '    }',
      '',
      '    @PostMapping("/otp/verify")',
      '    @RateLimiter(name = "otp")',
      '    public Token verify(@RequestBody OtpRequest body) {',
      '        return auth.verifyOtp(body);',
      '    }',
      '}',
    ].join('\n'))).toEqual(['4:high:Login without a rate limit']);
    expect(titles(otherRateLimitRule, 'src/main/kotlin/ng/nolt/PinController.kt', [
      '@RestController',
      'class PinController(private val pins: PinService) {',
      '    @PostMapping("/pin/verify")',
      '    fun verify(@RequestBody body: PinRequest): PinResult {',
      '        if (!bucket.tryConsume(1)) throw TooManyRequests()',
      '        return pins.verify(body)',
      '    }',
      '',
      '    @PostMapping("/pin/change")',
      '    fun change(@RequestBody body: PinChange): PinResult = pins.change(body)',
      '}',
    ].join('\n'))).toEqual(['9:high:PIN check without a rate limit']);
  });

  it('honours a project-wide limit in any language', () => {
    const ctx = buildContext([file('Program.cs', 'builder.Services.AddRateLimiter(o => o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(c => default));\napp.UseRateLimiter();')]);
    expect(ctx.rateLimitAll).toBe(true);
    expect(otherRateLimitRule.run(file('Controllers/A.cs', '[HttpPost("login")]\npublic IActionResult Login() { return Ok(); }'), ctx)).toEqual([]);
  });
});

describe('FX-JWT-001 in Go, C#, PHP, Java and Kotlin', () => {
  it('Go (golang-jwt)', () => {
    expect(titles(otherTokenRule, 'auth/jwt.go', [
      'package auth',
      'func Issue(id string) (string, error) {',
      '\ttoken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": id})',
      '\treturn token.SignedString([]byte("nolt-secret"))',
      '}',
      'func Peek(raw string) {',
      '\tt, _, _ := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})',
      '\t_ = t',
      '}',
      'func Secret() string {',
      '\tsecret := os.Getenv("JWT_SECRET")',
      '\tif secret == "" {',
      '\t\tsecret = "changeme"',
      '\t}',
      '\treturn secret',
      '}',
      'func Safe(id string) (string, error) {',
      '\tclaims := jwt.RegisteredClaims{Subject: id, ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute))}',
      '\treturn jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)',
      '}',
    ].join('\n'))).toEqual([
      '3:medium:JWT issued without an expiry',
      '4:high:JWT signed with a hard-coded secret',
      '7:critical:JWT accepted without checking its signature',
      '11:high:Signing secret falls back to a hard-coded value',
    ]);
  });

  it('C# (JwtBearer)', () => {
    expect(titles(otherTokenRule, 'Program.cs', [
      'builder.Services.AddAuthentication().AddJwtBearer(o => {',
      '    o.TokenValidationParameters = new TokenValidationParameters {',
      '        ValidateIssuerSigningKey = false,',
      '        ValidateLifetime = false,',
      '        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("nolt-signing-key-123")),',
      '    };',
      '});',
      'var key = builder.Configuration["Jwt:Key"] ?? "fallback-key";',
      'var opts = new CookieOptions { HttpOnly = false, Secure = true };',
    ].join('\n'))).toEqual([
      '3:critical:JWT accepted without checking its signature',
      '4:high:JWT expiry not checked',
      '5:high:JWT signed with a hard-coded secret',
      '8:high:Signing secret falls back to a hard-coded value',
      '9:medium:Session cookie readable by scripts (HttpOnly off)',
    ]);
  });

  it('PHP (firebase/php-jwt, Laravel config)', () => {
    expect(titles(otherTokenRule, 'app/Services/TokenService.php', [
      '<?php',
      'class TokenService {',
      '    public function issue($user) {',
      "        return JWT::encode(['sub' => $user->id], 'nolt-secret', 'HS256');",
      '    }',
      '    public function read($jwt) {',
      "        return JWT::decode($jwt, new Key(env('JWT_SECRET', 'changeme'), 'HS256'));",
      '    }',
      '    public function issueSafe($user) {',
      "        return JWT::encode(['sub' => $user->id, 'exp' => time() + 900], config('jwt.secret'), 'HS256');",
      '    }',
      '}',
    ].join('\n'))).toEqual([
      '4:high:JWT signed with a hard-coded secret',
      '7:high:Signing secret falls back to a hard-coded value',
    ]);
    expect(titles(otherTokenRule, 'config/session.php', "<?php\nreturn [\n    'secure' => false,\n    'http_only' => false,\n    'same_site' => 'lax',\n];")).toEqual([
      '3:medium:Session cookie sent over plain HTTP (Secure off)',
      '4:medium:Session cookie readable by scripts (HttpOnly off)',
    ]);
  });

  it('Java and Kotlin (jjwt, auth0)', () => {
    expect(titles(otherTokenRule, 'src/main/java/ng/nolt/JwtService.java', [
      'public class JwtService {',
      '    @Value("${jwt.secret:changeme}")',
      '    private String secret;',
      '    public String issue(String id) {',
      '        return Jwts.builder().setSubject(id).signWith(Keys.hmacShaKeyFor("nolt-secret-key-that-is-long-enough".getBytes())).compact();',
      '    }',
      '    public Claims peek(String token) {',
      '        return Jwts.parser().parseClaimsJwt(token).getBody();',
      '    }',
      '}',
    ].join('\n'))).toEqual([
      '2:high:Signing secret falls back to a hard-coded value',
      '5:high:JWT signed with a hard-coded secret',
      '8:critical:JWT accepted without checking its signature',
    ]);
    expect(titles(otherTokenRule, 'src/main/kotlin/ng/nolt/Tokens.kt', [
      'fun issue(id: String): String =',
      '    JWT.create().withSubject(id).sign(Algorithm.HMAC256("nolt-secret"))',
      'fun cookie(): Cookie = Cookie("session", "x").apply { isHttpOnly = true; secure = true }',
    ].join('\n'))).toEqual(['2:high:JWT signed with a hard-coded secret']);
  });

  it('leaves safe code alone', () => {
    expect(lines(otherTokenRule, 'auth/safe.go', 'func Read(raw string) (*jwt.Token, error) {\n\treturn jwt.Parse(raw, func(t *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}))\n}')).toEqual([]);
    expect(lines(otherTokenRule, 'Program.cs', 'o.TokenValidationParameters = new TokenValidationParameters { ValidateIssuerSigningKey = true, ValidateLifetime = true, IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)) };')).toEqual([]);
  });
});

describe('FX-RESET-001 in Go, C#, PHP, Java and Kotlin', () => {
  it('Go: weak codes, Host-header links and leaked codes, but only with math/rand', () => {
    const text = [
      'package auth',
      'import (',
      '\t"math/rand"',
      ')',
      'func (h *Handler) ForgotPassword(c *gin.Context) {',
      '\tcode := fmt.Sprintf("%06d", rand.Intn(1000000))',
      '\tlink := "https://" + c.Request.Host + "/reset?code=" + code',
      '\tlog.Printf("reset code %s", code)',
      '\tmailer.Send(c.PostForm("email"), link)',
      '\tc.JSON(200, gin.H{"sent": true, "code": code})',
      '}',
    ].join('\n');
    expect(titles(otherResetRule, 'auth/reset.go', text)).toEqual([
      "6:high:Password reset code can be guessed",
      "7:high:Password reset link built from the request's Host header",
      '8:high:Password reset token written to logs',
      '10:high:Password reset token returned in the API response',
    ]);
    expect(lines(otherResetRule, 'auth/reset.go', text.replace('"math/rand"', '"crypto/rand"'))).toEqual([7, 8, 10]);
  });

  it('C#: reset tokens that never expire, and enumeration', () => {
    expect(titles(otherResetRule, 'Controllers/PasswordController.cs', [
      'public class PasswordController : ControllerBase',
      '{',
      '    [HttpPost("password/reset")]',
      '    public async Task<IActionResult> ResetPassword([FromBody] ResetDto dto)',
      '    {',
      '        var row = await _db.Resets.FirstAsync(r => r.Token == dto.Token);',
      '        await _users.SetPassword(row.UserId, dto.NewPassword);',
      '        return Ok();',
      '    }',
      '',
      '    [HttpPost("password/forgot")]',
      '    public async Task<IActionResult> ForgotPassword([FromBody] ForgotDto dto)',
      '    {',
      '        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);',
      '        if (user == null) return NotFound("User not found");',
      '        await _mail.SendReset(user);',
      '        return Ok();',
      '    }',
      '}',
    ].join('\n'))).toEqual(['4:medium:Password reset token accepted without an expiry check', '15:low:Password reset says whether an account exists']);
  });

  it('PHP: Laravel reset closures and controllers', () => {
    expect(titles(otherResetRule, 'routes/web.php', [
      '<?php',
      "Route::post('/pin/forgot', function (Request $request) {",
      '    $code = rand(1000, 9999);',
      "    $link = $request->root() . '/pin/reset?code=' . $code;",
      "    Log::info('pin reset', ['code' => $code]);",
      "    return response()->json(['sent' => true, 'code' => $code]);",
      '});',
    ].join('\n'))).toEqual([
      '3:high:PIN reset code can be guessed',
      "4:high:PIN reset link built from the request's Host header",
      '5:high:PIN reset token written to logs',
      '6:high:PIN reset token returned in the API response',
    ]);
    expect(lines(otherResetRule, 'app/Http/Controllers/ResetController.php', [
      '<?php',
      'class ResetController {',
      '    public function forgotPassword(Request $request) {',
      '        $token = Str::random(64);',
      "        Mail::to($request->email)->send(new ResetMail(config('app.url') . '/reset/' . $token));",
      "        return response()->json(['message' => 'If that account exists, we sent a link.']);",
      '    }',
      '}',
    ].join('\n'))).toEqual([]);
  });

  it('Java and Kotlin: Spring resets', () => {
    expect(titles(otherResetRule, 'src/main/java/ng/nolt/ResetController.java', [
      'public class ResetController {',
      '    @PostMapping("/password/forgot")',
      '    public Map<String, String> forgotPassword(@RequestBody ForgotRequest body, HttpServletRequest request) {',
      '        String code = String.valueOf(new Random().nextInt(900000) + 100000);',
      '        String link = request.getRequestURL() + "?code=" + code;',
      '        mail.send(body.getEmail(), link);',
      '        return Map.of("sent", "true", "code", code);',
      '    }',
      '}',
    ].join('\n'))).toEqual([
      '4:high:Password reset code can be guessed',
      "5:high:Password reset link built from the request's Host header",
      '7:high:Password reset token returned in the API response',
    ]);
    expect(titles(otherResetRule, 'src/main/kotlin/ng/nolt/PinReset.kt', [
      'class PinReset(private val repo: PinResetRepository) {',
      '    @PostMapping("/pin/reset")',
      '    fun resetPin(@RequestBody body: ResetRequest): ResponseEntity<Unit> {',
      '        val row = repo.findByCode(body.code)',
      '        if (row.expiresAt.isBefore(Instant.now())) throw Expired()',
      '        wallets.setPin(row.userId, passwordEncoder.encode(body.newPin))',
      '        return ResponseEntity.ok().build()',
      '    }',
      '}',
    ].join('\n'))).toEqual(['3:medium:PIN reset token can be used more than once']);
  });

  it('ignores functions that reset something else', () => {
    expect(lines(otherResetRule, 'ui/form.go', 'package ui\nimport "math/rand"\nfunc ResetForm(f *Form) {\n\tf.Seed = rand.Intn(10)\n}')).toEqual([]);
  });
});
