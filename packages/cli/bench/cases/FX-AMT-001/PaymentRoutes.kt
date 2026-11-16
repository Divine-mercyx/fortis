package ng.paywave.payments

@RestController
class PaymentController(private val flutterwave: FlutterwaveClient) {
    @PostMapping("/pay")
    fun pay(@RequestBody request: PayRequest) = flutterwave.charge(request.email, request.amount) // @hit

    @PostMapping("/order")
    fun order(@RequestBody body: OrderRequest): Any {
        val amount = body.amount
        return flutterwave.initiate(body.email, amount) // @hit
    }

    @PostMapping("/plan")
    fun plan(@RequestBody request: PlanRequest): Any {
        val plan = plans.find(request.planId)
        return flutterwave.charge(request.email, plan.priceKobo)
    }

    @PostMapping("/wallet/top-up")
    fun topUp(@RequestBody request: TopUpRequest) = flutterwave.charge(request.email, request.amount)
}
