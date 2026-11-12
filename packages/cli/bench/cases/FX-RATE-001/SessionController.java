package ng.nolt.auth;

@RestController
public class SessionController {
    @PostMapping("/auth/signin") // @hit
    public Token signin(@RequestBody LoginRequest body) {
        return auth.login(body);
    }

    @PostMapping("/accounts")
    public Account open(@RequestBody OpenAccount body) {
        return accounts.open(body);
    }
}
