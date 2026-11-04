public class Client {
    private static final String API_KEY = "{{GENERIC}}"; // @hit
    private final String secret = System.getProperty("payment.secret.value.from.jvm");
    @Value("${payment.api.token.value}") private String token;
}
