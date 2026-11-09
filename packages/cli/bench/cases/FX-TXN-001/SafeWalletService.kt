@Service
class SafeWalletKtService(private val walletRepository: WalletRepository) {
    @Transactional
    fun debit(id: Long, amount: Long) {
        val wallet = walletRepository.findById(id).orElseThrow()
        wallet.balance -= amount
        walletRepository.save(wallet)
    }
}
