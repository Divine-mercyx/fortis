@RestController
public class SafeProfileController {
    private final ProfileRepository repository;

    @GetMapping("/profiles/{id}")
    public Profile get(@PathVariable Long id) {
        return repository.findById(id).orElseThrow();
    }
}
