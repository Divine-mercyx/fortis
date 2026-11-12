package ng.nolt.auth;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @PostMapping("/login") // @hit
    public Token login(@RequestBody LoginRequest body) {
        return auth.login(body);
    }

    @PostMapping("/otp/verify")
    @RateLimiter(name = "otp")
    public Token verifyOtp(@RequestBody OtpRequest body) {
        return auth.verifyOtp(body);
    }

    @PostMapping("/pin/verify") // @hit
    public PinResult verifyPin(@RequestBody PinRequest body) {
        return pins.verify(body);
    }

    @PostMapping("/password/forgot") // @hit
    public void forgot(@RequestBody ForgotRequest body) {
        resets.send(body.getEmail());
    }

    @PostMapping(value = "/2fa") // @hit
    public Token twoFactor(@RequestBody TotpRequest body) {
        return auth.verifyTotp(body);
    }

    @PostMapping("/sign-in/phone")
    public Token phone(@RequestBody PhoneLogin body) {
        if (!bucket.tryConsume(1)) throw new TooManyRequestsException();
        return auth.loginWithPhone(body);
    }

    @PostMapping("/logout")
    public void logout() {}
}
