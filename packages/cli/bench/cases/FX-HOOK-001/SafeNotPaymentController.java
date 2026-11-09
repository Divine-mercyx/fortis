@RestController
public class SafeNotPaymentController {
    @PostMapping("/webhooks/github")
    public void receive(@RequestBody String body) {}
}
