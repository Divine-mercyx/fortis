class SafeOtpKtService {
    private val random = SecureRandom()

    fun makeOtp(): String {
        val otp = random.nextInt(900000) + 100000
        return otp.toString()
    }

    fun respond() = ResponseEntity.ok(mapOf("sent" to true))
}
