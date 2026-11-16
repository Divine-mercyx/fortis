package ng.paywave.charges

@RestController
class ChargeController(private val stripe: StripeClient, private val monnify: MonnifyClient) {
    @PostMapping("/stripe")
    fun stripe(@RequestBody req: ChargeRequest): Any {
        val params = PaymentIntentCreateParams.builder().setAmount(req.amount).build()
        return stripe.paymentIntents().create(params) // @hit
    }

    @PostMapping("/monnify")
    fun monnify(@RequestBody dto: ChargeRequest) = monnify.initializeTransaction(dto.email, dto.amount) // @hit

    @PostMapping("/paystack")
    fun paystack(@RequestBody payload: ChargeRequest): Any {
        val kobo = payload.amount * 100
        return paystackClient.initialize(payload.email, kobo) // @hit
    }

    @PostMapping("/invoice")
    fun invoice(@RequestBody req: InvoiceRequest): Any {
        val invoice = invoices.find(req.invoiceId)
        return paystackClient.initialize(req.email, invoice.amount)
    }

    @PostMapping("/subscription")
    fun subscribe(@RequestBody req: SubscribeRequest): Any {
        val price = pricing.priceFor(req.plan)
        return stripe.paymentIntents().create(params(price))
    }

    fun fromJob(order: Order) = paystackClient.initialize(order.email, order.amount)
}
