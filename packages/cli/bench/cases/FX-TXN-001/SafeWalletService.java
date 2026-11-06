@Service
public class SafeWalletService {
    @Transactional
    public void debit(Long id, long amount) {
        Wallet wallet = walletRepository.findById(id).orElseThrow();
        wallet.setBalance(wallet.getBalance() - amount);
        walletRepository.save(wallet);
    }

    public void locked(Long id, long amount) {
        transactionTemplate.execute(status -> {
            Wallet wallet = walletRepository.findById(id).orElseThrow();
            wallet.setBalance(wallet.getBalance() - amount);
            return walletRepository.save(wallet);
        });
    }
}
