@Service
public class WalletService {
    public void debit(Wallet wallet, long amount) {
        wallet.setBalance(wallet.getBalance() - amount); // @hit
        walletRepository.save(wallet);
    }

    public void credit(Wallet wallet, BigDecimal amount) {
        wallet.setBalance(wallet.getBalance().add(amount)); // @hit
        walletRepository.save(wallet);
    }

    public void hold(Wallet wallet, BigDecimal amount) {
        wallet.setAvailableBalance(wallet.getAvailableBalance().subtract(amount)); // @hit
        walletRepository.saveAndFlush(wallet);
    }

    public void settle(Account account, long amount) {
        account.setLedgerBalance(account.getLedgerBalance() + amount); // @hit
        accountRepository.save(account);
    }

    public void reverse(Account account, long amount) {
        account.setBalance(account.getBalance() + amount); // @hit
        jdbcTemplate.update("UPDATE accounts SET balance = ?", account.getBalance());
    }

    public long preview(Wallet wallet, long amount) {
        wallet.setBalance(wallet.getBalance() - amount);
        return wallet.getBalance();
    }
}
