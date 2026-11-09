@RestController
public class WalletReadController {
    private final WalletRepository repository;

    @GetMapping("/wallets/{id}")
    public Wallet get(@PathVariable Long id) {
        return repository.findById(id).orElseThrow(); // @hit
    }

    @GetMapping("/wallets/{id}/summary")
    public Wallet summary(@PathVariable Long id) {
        return walletService.getWalletById(id); // @hit
    }
}
