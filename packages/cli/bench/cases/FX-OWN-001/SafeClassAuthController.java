@RestController
@PreAuthorize("hasRole('ADMIN')")
public class SafeClassAuthController {
    @GetMapping("/invoices/{id}")
    public Invoice get(@PathVariable Long id) {
        return invoiceRepository.findById(id).orElseThrow();
    }
}
