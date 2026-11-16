// The same shape, but the service it calls only logs.
@RestController
public class CardLoginController {
  private final CardLoginService logins;
  public CardLoginController(CardLoginService logins) { this.logins = logins; }
  @PostMapping("/card/login") // @hit
  public TokenResponse login(@RequestBody LoginRequest body) {
    return logins.authenticate(body);
  }
}
