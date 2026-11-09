@Service
class WalletService(private val walletRepository: WalletRepository) {
    fun debit(wallet: Wallet, amount: Long) {
        wallet.balance -= amount // @hit
        walletRepository.save(wallet)
    }

    fun credit(wallet: Wallet, amount: Long) {
        wallet.balance = wallet.balance + amount // @hit
        walletRepository.save(wallet)
    }

    fun hold(wallet: Wallet, amount: BigDecimal) {
        wallet.availableBalance = wallet.availableBalance.subtract(amount) // @hit
        walletRepository.save(wallet)
    }

    fun settle(account: Account, amount: Long) {
        account.ledgerBalance += amount // @hit
        accountRepository.saveAndFlush(account)
    }

    fun reverse(account: Account, amount: BigDecimal) {
        account.balance = account.balance.plus(amount) // @hit
        accountRepository.save(account)
    }

    fun preview(wallet: Wallet, amount: Long): Long {
        wallet.balance -= amount
        return wallet.balance
    }
}
