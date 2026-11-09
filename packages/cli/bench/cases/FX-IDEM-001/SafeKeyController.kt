@RestController
class SafeKeyKtController {
    @PostMapping("/transfers")
    fun transfer(@RequestHeader("Idempotency-Key") key: String) {}
}
