// The expiry check and the delete are in the token service: no finding.
@RestController
public class WalletResetController {
  private final WalletResetTokens tokens;
  public WalletResetController(WalletResetTokens tokens) { this.tokens = tokens; }
  @PostMapping("/wallet/password/reset")
  public void resetPassword(@RequestBody ResetRequest request) {
    User user = tokens.redeem(request.getToken());
    user.setPassword(passwordEncoder.encode(request.getNewPassword()));
  }
}
