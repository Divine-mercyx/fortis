package ng.paywave.charges;

@RestController
public class ChargeController {
    @PostMapping("/stripe")
    public Object stripe(@RequestBody ChargeRequest req) throws Exception {
        PaymentIntentCreateParams params = PaymentIntentCreateParams.builder().setAmount(req.getAmount()).setCurrency("ngn").build();
        return stripeClient.paymentIntents().create(params); // @hit
    }

    @PostMapping("/monnify")
    public Object monnify(@RequestBody ChargeRequest dto) {
        return monnifyService.initializeTransaction(dto.getEmail(), dto.getAmount()); // @hit
    }

    @PostMapping("/flutterwave")
    public Object flw(@RequestParam long amount, @RequestBody ChargeRequest payload) {
        BigDecimal total = BigDecimal.valueOf(payload.getAmount());
        return flutterwaveClient.charge(payload.getEmail(), total); // @hit
    }

    @PostMapping("/invoice")
    public Object invoice(@RequestBody InvoiceRequest req) {
        Invoice invoice = invoices.findById(req.getInvoiceId()).orElseThrow();
        if (!invoice.getAmount().equals(req.getAmount())) throw new IllegalArgumentException("amount");
        return paystackClient.initialize(req.getEmail(), invoice.getAmount());
    }

    @PostMapping("/subscription")
    public Object subscribe(@RequestBody SubscribeRequest req) {
        long price = pricing.priceFor(req.getPlan());
        return stripeClient.paymentIntents().create(params(price));
    }

    public Object fromJob(Order order) {
        return paystackClient.initialize(order.getEmail(), order.getAmount());
    }
}
