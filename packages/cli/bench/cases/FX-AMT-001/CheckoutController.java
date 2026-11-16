package ng.paywave.checkout;

@RestController
@RequestMapping("/checkout")
public class CheckoutController {
    private final PaystackClient paystackClient;
    private final RestTemplate restTemplate;

    @PostMapping("/pay")
    public ResponseEntity<?> pay(@RequestBody CheckoutRequest request) {
        return ResponseEntity.ok(paystackClient.initialize(request.getEmail(), request.getAmount())); // @hit
    }

    @PostMapping("/order")
    public ResponseEntity<?> order(@RequestBody OrderRequest request) {
        long amount = request.getAmount() * 100;
        var body = Map.of("email", request.getEmail(), "amount", amount);
        return restTemplate.postForEntity("https://api.paystack.co/transaction/initialize", body, Map.class); // @hit
    }

    @PostMapping("/plan")
    public ResponseEntity<?> plan(@RequestBody PlanRequest request) {
        Plan plan = plans.findById(request.getPlanId()).orElseThrow();
        return ResponseEntity.ok(paystackClient.initialize(request.getEmail(), plan.getPriceKobo()));
    }

    @PostMapping("/cart")
    public ResponseEntity<?> cart(@RequestBody CartRequest request) {
        long total = cartService.totalFor(request.getCartId());
        return ResponseEntity.ok(paystackClient.initialize(request.getEmail(), total));
    }

    @GetMapping("/amount")
    public long amount(@RequestBody CartRequest request) {
        return request.getAmount();
    }
}
