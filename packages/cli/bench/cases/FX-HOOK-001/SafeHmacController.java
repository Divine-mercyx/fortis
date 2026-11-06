// Paystack events
@RestController
public class SafeHmacController {
    @PostMapping("/webhooks/paystack")
    public void receive(@RequestBody String body, @RequestHeader("x-paystack-signature") String signature) {
        Mac mac = Mac.getInstance("HmacSHA512");
        byte[] expected = mac.doFinal(body.getBytes());
        if (!MessageDigest.isEqual(expected, signature.getBytes())) throw new ForbiddenException();
    }
}
