@Service
@Transactional
public class SafeClassTransaction {
    public void debit(Wallet wallet, long amount) {
        wallet.setBalance(wallet.getBalance() - amount);
        walletRepository.save(wallet);
    }
}
