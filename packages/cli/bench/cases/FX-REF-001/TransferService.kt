package ng.paywave.transfers

import java.util.UUID
import kotlin.random.Random

class TransferService {
    fun send(order: Order) {
        val reference = "TRF${System.currentTimeMillis()}" // @hit
        val txRef: String = "PAY-" + Random.nextInt(999999) // @hit
        val paymentRef = "PW" + (100000..999999).random() // @hit
        val payload = Payload(reference = "ORD" + Instant.now().toEpochMilli()) // @hit
        val safeRef = "TRF-${UUID.randomUUID()}"
        val existingRef = order.reference
        val href = "https://paywave.ng/${System.currentTimeMillis()}"
        val createdAt = System.currentTimeMillis()
        val requestId = "REQ${System.currentTimeMillis()}"
    }
}
