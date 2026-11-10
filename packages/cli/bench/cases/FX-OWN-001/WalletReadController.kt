@RestController
class WalletReadKtController(private val repository: WalletRepository) {
    @GetMapping("/wallets/{id}")
    fun get(@PathVariable id: Long) = repository.findById(id).orElseThrow() // @hit

    @GetMapping("/wallets/{id}/summary")
    fun summary(@PathVariable id: Long) = walletService.getWalletById(id) // @hit
}
