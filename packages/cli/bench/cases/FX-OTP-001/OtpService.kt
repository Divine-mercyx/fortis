class OtpService {
    fun makeOtp(): String {
        val otp = Random().nextInt(900000) + 100000 // @hit
        return otp.toString()
    }

    fun resetCode(): String {
        val resetCode = (100000..999999).random() // @hit
        return resetCode.toString()
    }

    fun send(otp: String, phone: String) {
        log.info("otp $otp for $phone") // @hit
        println("otp $otp") // @hit
    }

    fun respond(otp: String) = ResponseEntity.ok(mapOf("sent" to true, "otp" to otp)) // @hit

    fun review() {
        log.info("reviewer otp is 482901") // @hit
    }

    fun delay(): Int {
        val delay = Random().nextInt(100)
        return delay
    }
}
