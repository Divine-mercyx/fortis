public class KycLookupService {
    public void verify(Customer customer) {
        log.info("{}", bvnResponseData.toString()); // @hit
        log.info("{}", bvnVerified);
        log.info("{}", ninStatus);
    }
}
