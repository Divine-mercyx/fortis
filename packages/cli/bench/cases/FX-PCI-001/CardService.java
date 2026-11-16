package ng.paywave.cards;

public class CardService {
    private static final Logger log = LoggerFactory.getLogger(CardService.class);

    public void charge(ChargeRequest request) {
        log.info("charging card {}", request.getCardNumber()); // @hit
        log.debug("cvv {} expiry {}", request.getCvv(), request.getExpiry()); // @hit
        System.out.println("card " + request.getCard().getPan()); // @hit
        log.error("payment failed for card_number={}", cardNumber); // @hit
        log.info("charging card ending {}", maskPan(request.getCardNumber()));
        log.info("card last4 {}", request.getLast4());
        log.info("has cvv: {}", request.getCvv() != null);
        log.info("card brand {} for {}", request.getBrand(), request.getEmail());
        log.info("authorization {}", authorizationCode);
        log.warn("card declined: {}", response.getMessage());
        String number = request.getCardNumber();
    }
}
