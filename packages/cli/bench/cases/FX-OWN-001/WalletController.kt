@RestController
@RequestMapping("/wallets")
class WalletController(private val walletRepository: WalletRepository) {
    @GetMapping("/{id}")
    fun get(@PathVariable id: Long) = walletRepository.findById(id).orElseThrow() // @hit

    @GetMapping("/{walletId}/balance")
    fun balance(@PathVariable walletId: UUID): Wallet {
        val wallet = walletRepository.findByIdOrNull(walletId) // @hit
        return wallet!!
    }

    @DeleteMapping("/{id}")
    fun delete(@PathVariable id: Long) {
        walletRepository.getReferenceById(id) // @hit
    }

    @PutMapping("/{id}/transfer")
    fun transfer(@PathVariable id: Long): Transfer {
        return transferService.getById(id) // @hit
    }

    @GetMapping("/payments/{id}")
    fun payment(@PathVariable id: Long) = paymentRepository.findById(id) // @hit
}
