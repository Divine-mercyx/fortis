@Service
public class HelperService {
    public void receive(Long id, long amount) {
        Wallet wallet = walletRepository.findById(id).orElseThrow();
        credit(wallet, amount);
        walletRepository.save(wallet);
    }

    private void credit(Wallet wallet, long amount) {
        wallet.setBalance(wallet.getBalance() + amount); // @hit
    }
}
