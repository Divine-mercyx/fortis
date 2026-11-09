// Sends Paystack test events to our own staging service
@FeignClient(name = "staging")
public interface SafeFeignClient {
    @PostMapping("/webhooks/paystack")
    void send(@RequestBody String body);
}
