@RestController
class CardPinController(private val pins: CardPinService) {
    @PostMapping("/card/pin/verify") // @hit
    fun verify(@RequestBody body: PinRequest) = pins.verify(body)
}

@Service
class CardPinService(private val audit: Auditor) {
    fun verify(body: PinRequest): Boolean {
        audit.record(body.userId)
        return matches(body)
    }
}
