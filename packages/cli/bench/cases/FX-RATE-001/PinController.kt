package ng.nolt.pin

@RestController
@RequestMapping("/api/pin")
class PinController(private val pins: PinService) {
    @PostMapping("/verify") // @hit
    fun verify(@RequestBody body: PinRequest): PinResult = pins.verify(body)

    @PostMapping("/change") // @hit
    fun change(@RequestBody body: PinChange): PinResult {
        return pins.change(body)
    }

    @PostMapping("/otp") // @hit
    fun otp(@RequestBody body: OtpRequest): Result {
        return pins.verifyOtp(body)
    }

    @PostMapping("/unlock")
    fun unlock(@RequestBody body: PinRequest): PinResult {
        if (attempts.failedAttempts(body.userId) > 5) throw Locked()
        return pins.unlockWithPin(body)
    }

    @PostMapping("/login") // @hit
    fun login(@RequestBody body: LoginRequest): Token {
        return auth.login(body)
    }

    @PostMapping("/2fa") // @hit
    fun twoFactor(@RequestBody body: TotpRequest): Token {
        return auth.verifyTotp(body)
    }
}
