public class SafeOtpService {
    private static final SecureRandom RANDOM = new SecureRandom();

    public String makeOtp() {
        int otp = RANDOM.nextInt(900000) + 100000;
        return String.valueOf(otp);
    }

    public ResponseEntity<?> respond() {
        log.info("otp sent");
        return ResponseEntity.ok(Map.of("sent", true));
    }
}
