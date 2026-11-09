// Paystack, Flutterwave, Kora, Remita and Monnify events
@RestController
class HooksKtController {
    @PostMapping("/webhooks/paystack") // @hit
    fun paystack(@RequestBody body: String) {}

    @PostMapping("/flutterwave/webhook") // @hit
    fun flutterwave(@RequestBody body: String) {}

    @PostMapping("/kora/webhook") // @hit
    fun kora(@RequestBody body: String) {}

    @PostMapping("/remita/webhook") // @hit
    fun remita(@RequestBody body: String) {}

    @RequestMapping("/monnify/webhook", method = [RequestMethod.POST]) // @hit
    fun monnify(@RequestBody body: String) {}

    @GetMapping("/webhooks/health")
    fun health() {}
}
