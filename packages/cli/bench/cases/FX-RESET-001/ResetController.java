package ng.nolt.auth;

public class ResetController {
    @PostMapping("/password/forgot")
    public Map<String, String> forgotPassword(@RequestBody ForgotRequest body, HttpServletRequest request) {
        String code = String.valueOf(new Random().nextInt(900000) + 100000); // @hit
        String link = request.getRequestURL() + "?code=" + code; // @hit
        log.info("reset code {} for {}", code, body.getEmail()); // @hit
        mail.send(body.getEmail(), link);
        return Map.of("sent", "true", "code", code); // @hit
    }

    @PostMapping("/password/reset")
    public void resetPassword(@RequestBody ResetRequest body) { // @hit
        PasswordReset row = resets.findByToken(body.getToken());
        users.setPassword(row.getUserId(), passwordEncoder.encode(body.getNewPassword()));
    }

    @PostMapping("/password/reset-safe")
    public void resetPasswordSafe(@RequestBody ResetRequest body) {
        PasswordReset row = resets.findByToken(body.getToken());
        if (row.getExpiresAt().isBefore(Instant.now())) throw new ExpiredException();
        users.setPassword(row.getUserId(), passwordEncoder.encode(body.getNewPassword()));
        resets.delete(row);
    }
}
