package ng.paywave.accounts

import java.math.BigDecimal

data class Account(
    val id: Long,
    val balance: Double, // @hit
    var availableBalance: Double?, // @hit
    val ledgerBalance: BigDecimal,
    val balanceKobo: Long,
    val interestRate: Double,
    val amountLabel: String,
)

data class TransferRequest(val amount: Float, val narration: String) // @hit

class TransferService {
    fun fee(amount: Double): BigDecimal = BigDecimal.ONE

    fun parse(request: TransferRequest) {
        val total = request.total.toDouble() // @hit
        val price = body.price.toDoubleOrNull() // @hit
        val kobo = (request.amount.toDouble() * 100).toLong()
        val ratio = request.ratio.toDouble()
        val count = request.count.toInt()
        val shown = "%.2f".format(ledgerBalance)
        val ok = request.amount.toDouble() > 0
    }

    fun latitude(): Double = 6.45
    fun score(weight: Double): Double = weight * 2
}
