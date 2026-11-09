// Paystack events
@RestController
public class PaymentWebhookController {
    @PostMapping("/paystack/events") // @hit
    public void receive(@RequestBody String body) {}
}
