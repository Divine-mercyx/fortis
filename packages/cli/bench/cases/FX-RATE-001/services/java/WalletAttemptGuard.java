@Component
public class WalletAttemptGuard {
  private final Bucket bucket;
  public void check(String key) {
    if (!bucket.tryConsume(1)) throw new TooManyRequestsException();
  }
}
