@Service
class HelperKtService(private val walletRepository: WalletRepository) {
    fun receive(id: Long, amount: Long) {
        val wallet = walletRepository.findById(id).orElseThrow()
        credit(wallet, amount)
        walletRepository.save(wallet)
    }

    private fun credit(wallet: Wallet, amount: Long) {
        wallet.balance += amount // @hit
    }
}
