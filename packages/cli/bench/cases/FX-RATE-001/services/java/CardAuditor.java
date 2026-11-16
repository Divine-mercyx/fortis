@Component
public class CardAuditor {
  public void record(String key) { log.info("login {}", key); }
}
