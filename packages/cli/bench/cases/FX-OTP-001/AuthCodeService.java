public class AuthCodeService {
    private static final Random RANDOM = new Random();

    public String generateAuthCode(String phone) {
        StringBuilder sb = new StringBuilder();
        Random random = new Random(); // @hit
        for (int i = 0; i < 6; i++) sb.append(random.nextInt(10));
        return sb.toString();
    }

    public String makeOtp() {
        return String.valueOf(RANDOM.nextInt(999999)); // @hit
    }

    public int shipping() {
        int shipping = new Random().nextInt(3);
        return shipping;
    }

    public int mapping() {
        int mapping = RANDOM.nextInt(3);
        return mapping;
    }

    public int footprint() {
        int footprint = new Random().nextInt(3);
        return footprint;
    }

    public String zip() {
        String zipCode = String.valueOf(new Random().nextInt(99999));
        return zipCode;
    }
}
