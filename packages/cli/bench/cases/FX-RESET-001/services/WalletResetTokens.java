@Service
public class WalletResetTokens {
  public User redeem(String token) {
    ResetToken t = repo.findByToken(token).orElseThrow();
    if (t.getExpiresAt().isBefore(Instant.now())) throw new ExpiredException();
    repo.delete(t);
    return t.getUser();
  }
}
