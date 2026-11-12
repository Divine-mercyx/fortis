package ng.nolt.pin

class PinResetController(private val repo: PinResetRepository) {
    @PostMapping("/pin/forgot")
    fun forgotPin(@RequestBody body: ForgotPin, request: HttpServletRequest): Map<String, String> {
        val code = (100000..999999).random().toString() // @hit
        val link = "${request.requestURL}?code=$code" // @hit
        logger.info("pin reset code $code") // @hit
        sms.send(body.phone, link)
        return mapOf("sent" to "true", "code" to code) // @hit
    }

    @PostMapping("/pin/reset")
    fun resetPin(@RequestBody body: ResetRequest): ResponseEntity<Unit> { // @hit
        val row = repo.findByCode(body.code)
        if (row.expiresAt.isBefore(Instant.now())) throw Expired()
        wallets.setPin(row.userId, passwordEncoder.encode(body.newPin))
        return ResponseEntity.ok().build()
    }
}
