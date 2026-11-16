// The limiter is two calls away, in another file: no finding.
@RestController
public class WalletLoginController {
  private final WalletLoginService logins;
  public WalletLoginController(WalletLoginService logins) { this.logins = logins; }
  @PostMapping("/wallet/login")
  public TokenResponse login(@RequestBody LoginRequest body) {
    return logins.authenticate(body);
  }
}
