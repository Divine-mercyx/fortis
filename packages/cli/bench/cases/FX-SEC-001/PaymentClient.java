public class PaymentClient {
  private static final String PAYSTACK = "{{PAYSTACK_LIVE}}"; // @hit
  private static final String OPAY = "{{OPAY_PRIVATE}}"; // @hit
  private final String fromEnv = System.getenv("PAYSTACK_SECRET_KEY");
}
