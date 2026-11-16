package ng.paywave.payments;

import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

public class PaymentService {
    public void pay(Order order) {
        String reference = "TXN" + System.currentTimeMillis(); // @hit
        String txRef = "PAY-" + new Random().nextInt(999999); // @hit
        String paymentReference = "PW" + (long) (Math.random() * 1e12); // @hit
        request.setReference("ORD-" + Instant.now().toEpochMilli()); // @hit
        ChargeRequest.builder().reference("CHG" + System.nanoTime()).build(); // @hit
        String safeRef = "TXN-" + UUID.randomUUID();
        String secureReference = "TXN" + System.currentTimeMillis() + UUID.randomUUID();
        String reference2 = order.getReference();
        String href = "https://paywave.ng/" + System.currentTimeMillis();
        long createdAt = System.currentTimeMillis();
        String requestId = "REQ" + System.currentTimeMillis();
        if (reference == null) return;
        String token = new SecureRandom().toString();
    }
}
