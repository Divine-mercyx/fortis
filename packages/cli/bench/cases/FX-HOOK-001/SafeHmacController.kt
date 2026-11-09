// Paystack events
@RestController
class SafeHmacKtController {
    @PostMapping("/webhooks/paystack")
    fun receive(@RequestBody body: String, @RequestHeader("x-paystack-signature") signature: String) {
        val mac = Mac.getInstance("HmacSHA512")
        if (!MessageDigest.isEqual(mac.doFinal(body.toByteArray()), signature.toByteArray())) throw ForbiddenException()
    }
}
