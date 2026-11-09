@RestController
class MoneyKtController {
    @PostMapping("/transfers") // @hit
    fun transfer() {}

    @PostMapping("/wallets/{id}/withdraw") // @hit
    fun withdraw() {}

    @PutMapping("/payouts/{id}") // @hit
    fun payout() {}

    @PostMapping("/send-money") // @hit
    fun send() {}

    @RequestMapping(value = ["/disbursements"], method = [RequestMethod.POST]) // @hit
    fun disburse() {}

    @PostMapping("/transfers/quote")
    fun quote() {}

    @GetMapping("/transfers")
    fun list() {}
}
