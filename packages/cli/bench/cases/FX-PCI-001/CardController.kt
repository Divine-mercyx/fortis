package ng.paywave.cards

@Entity
class StoredCard(
    @Id val id: Long,
    val cardNumber: String, // @hit
    val cardCvv: String?, // @hit
    val last4: String,
    val brand: String,
)

class CardController {
    private val log = LoggerFactory.getLogger(javaClass)

    fun charge(request: ChargeRequest) {
        log.info("charging ${request.cardNumber}") // @hit
        log.debug("cvv {}", request.cvv) // @hit
        println("pan " + card.pan) // @hit
        log.info("charging card ending ${request.cardNumber.takeLast(4)}")
        log.info("has cvv ${request.cvv != null}")
        log.info("card brand ${request.brand}")
        log.info("authorization ${auth.code}")
        val number = request.cardNumber
    }
}
