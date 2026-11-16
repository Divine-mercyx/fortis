// The token service deletes the token but never looks at when it expires.
@RestController
public class CardResetController {
  private final CardResetTokens tokens;
  public CardResetController(CardResetTokens tokens) { this.tokens = tokens; }
  @PostMapping("/card/password/reset")
  public void resetPassword(@RequestBody ResetRequest request) { // @hit
    User user = tokens.redeem(request.getToken());
    user.setPassword(passwordEncoder.encode(request.getNewPassword()));
  }
}
