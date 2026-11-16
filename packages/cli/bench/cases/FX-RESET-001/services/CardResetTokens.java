@Service
public class CardResetTokens {
  public User redeem(String token) {
    ResetToken t = repo.findByToken(token).orElseThrow();
    repo.delete(t);
    return t.getUser();
  }
}
