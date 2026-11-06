@Service
class LedgerKtService(private val accountRepository: AccountRepository) {
    fun computed(account: Account, amount: Long) {
        val newBalance = account.balance - amount
        account.balance = newBalance // @hit
        accountRepository.save(account)
    }

    fun open(account: Account) {
        account.balance = BigDecimal.ZERO
        accountRepository.save(account)
    }
}
