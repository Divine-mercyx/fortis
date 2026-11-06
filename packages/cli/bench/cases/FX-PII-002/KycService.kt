class KycService {
    fun verify(customer: Customer, bvn: String, nin: String) {
        log.info("checking {}", bvn) // @hit
        logger.error("failed for ${customer.nin}") // @hit
        log.debug("nin $nin") // @hit
        log.warn( // @hit
            "retry {}",
            customer.bvn,
        )
        println("bvn $bvn") // @hit

        log.info("checking bvn")
        log.info("present {}", customer.bvn != null)
        log.info("{}", mask(bvn))
        log.info("{}", customer.id)
    }
}
