@RestController
class SafeWalletKtController(private val walletRepository: WalletRepository) {
    @GetMapping("/a/{id}")
    @PreAuthorize("@owners.check(#id)")
    fun pre(@PathVariable id: Long) = walletRepository.findById(id).orElseThrow()

    @GetMapping("/b/{id}")
    fun principal(@PathVariable id: Long, @AuthenticationPrincipal user: User) = walletRepository.findById(id).orElseThrow()

    @GetMapping("/c/{id}")
    fun profile(@PathVariable id: Long) = profileRepository.findById(id).orElseThrow()

    fun internal(id: Long) = walletRepository.findById(id).orElseThrow()
}
