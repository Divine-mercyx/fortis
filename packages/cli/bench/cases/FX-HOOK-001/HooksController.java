// Paystack, Flutterwave, Monnify, Remita and OPay events
@RestController
public class HooksController {
    @PostMapping("/webhooks/paystack") // @hit
    public void paystack(@RequestBody String body) {}

    @PostMapping("/flutterwave/webhook") // @hit
    public void flutterwave(@RequestBody String body) {}

    @RequestMapping(value = "/monnify/webhook", method = RequestMethod.POST) // @hit
    public void monnify(@RequestBody String body) {}

    @PostMapping(path = "/remita/webhook") // @hit
    public void remita(@RequestBody String body) {}

    @PostMapping("/opay/webhook") // @hit
    public void opay(@RequestBody String body) {}

    @GetMapping("/webhooks/health")
    public void health() {}
}
