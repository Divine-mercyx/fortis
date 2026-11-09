// Paystack events
@RestController
class PaymentWebhookKtController {
    @PostMapping("/paystack/events") // @hit
    fun receive(@RequestBody body: String) {}
}
