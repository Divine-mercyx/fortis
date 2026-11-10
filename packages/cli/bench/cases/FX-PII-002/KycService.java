public class KycService {
    public void verify(Customer customer, String bvn, String nin) {
        log.info("checking {}", bvn); // @hit
        logger.error("failed for {}", customer.getNin()); // @hit
        LOG.debug("nin " + nin); // @hit
        log.warn("retry {} {}", // @hit
            customer.getId(),
            customer.getBvn());
        System.out.println("bvn " + bvn); // @hit

        log.info("checking bvn");
        log.info("present {}", customer.getBvn() != null);
        log.info("length {}", bvn.length());
        log.info("{}", mask(bvn));
        log.info("{}", customer.getId());
    }
}
