class AuthCodeKtService {
    private val random = Random()

    fun generateAuthCode(phone: String): String {
        val sb = StringBuilder()
        val generator = Random() // @hit
        repeat(6) { sb.append(generator.nextInt(10)) }
        return sb.toString()
    }

    fun makeOtp() = random.nextInt(999999).toString() // @hit

    fun shipping(): Int {
        val shipping = Random().nextInt(3)
        return shipping
    }
}
