class KycLookupKtService {
    fun verify(customer: Customer) {
        log.info("result $bvnResponseData") // @hit
        log.info("verified $bvnVerified")
    }
}
