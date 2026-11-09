public class OtpService {
    public String makeOtp() {
        int otp = new Random().nextInt(900000) + 100000; // @hit
        return String.valueOf(otp);
    }

    public String resetCode() {
        String resetCode = String.valueOf((int) (Math.random() * 1000000)); // @hit
        return resetCode;
    }

    public void send(String otp, String phone) {
        log.info("otp {} for {}", otp, phone); // @hit
        System.out.println("otp " + otp); // @hit
    }

    public ResponseEntity<?> respond(String otp) {
        return ResponseEntity.ok(Map.of("sent", true, "otp", otp)); // @hit
    }

    public void review() {
        log.info("reviewer otp is 482901"); // @hit
    }

    public int delay() {
        int delay = new Random().nextInt(100);
        return delay;
    }

    public String couponCode() {
        String couponCode = String.valueOf(new Random().nextInt(9999));
        return couponCode;
    }
}
