@RestController
public class SafeWalletController {
    @GetMapping("/a/{id}")
    @PreAuthorize("@owners.check(#id)")
    public Wallet pre(@PathVariable Long id) {
        return walletRepository.findById(id).orElseThrow();
    }

    @GetMapping("/b/{id}")
    @PostAuthorize("returnObject.owner == principal.username")
    public Wallet post(@PathVariable Long id) {
        return walletRepository.findById(id).orElseThrow();
    }

    @GetMapping("/c/{id}")
    public Wallet principal(@PathVariable Long id, Principal principal) {
        Wallet wallet = walletRepository.findById(id).orElseThrow();
        if (!wallet.getOwner().equals(principal.getName())) throw new ForbiddenException();
        return wallet;
    }

    @GetMapping("/d/{id}")
    public Profile profile(@PathVariable Long id) {
        return profileRepository.findById(id).orElseThrow();
    }

    public Wallet internal(Long id) {
        return walletRepository.findById(id).orElseThrow();
    }
}
