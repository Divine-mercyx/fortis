@Service
public class LedgerService {
    public void brackets(Account account, double amount) {
        account.setCurrentBalance((account.getCurrentBalance() - amount)); // @hit
        accountRepository.save(account);
    }

    public void local(Account account, BigDecimal amount) {
        var balance = account.getAccountBalance();
        account.setAccountBalance(balance.subtract(amount)); // @hit
        accountRepository.save(account);
    }

    public void computed(Account account, long amount) {
        long newBalance = account.getBalance() - amount;
        account.setBalance(newBalance); // @hit
        accountRepository.save(account);
    }

    public void open(Account account) {
        account.setBalance(BigDecimal.ZERO);
        accountRepository.save(account);
    }
}
