@RestController
class WalletPinController(private val pins: WalletPinService) {
    @PostMapping("/wallet/pin/verify")
    fun verify(@RequestBody body: PinRequest) = pins.verify(body)
}
