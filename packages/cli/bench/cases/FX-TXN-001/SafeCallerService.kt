@Service
class SafeCallerKtService(private val walletRepository: WalletRepository) {
    @Transactional
    fun receive(id: Long, amount: Long) {
        val wallet = walletRepository.findById(id).orElseThrow()
        handle(wallet, amount)
    }

    private fun handle(wallet: Wallet, amount: Long) {
        credit(wallet, amount)
    }

    private fun credit(wallet: Wallet, amount: Long) {
        wallet.balance += amount
        walletRepository.save(wallet)
    }
}
