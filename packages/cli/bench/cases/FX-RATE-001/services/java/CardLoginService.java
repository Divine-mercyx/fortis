@Service
public class CardLoginService {
  private final CardAuditor auditor;
  public CardLoginService(CardAuditor auditor) { this.auditor = auditor; }
  public TokenResponse authenticate(LoginRequest body) {
    auditor.record(body.getEmail());
    return issue(body);
  }
}
