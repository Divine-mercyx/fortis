@Service
public class WalletLoginService {
  private final WalletAttemptGuard guard;
  public WalletLoginService(WalletAttemptGuard guard) { this.guard = guard; }
  public TokenResponse authenticate(LoginRequest body) {
    guard.check(body.getEmail());
    return issue(body);
  }
}
