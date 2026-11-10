@RestController
public class AdminLoanController {
    @GetMapping("/admin/loans/{id}")
    public Loan get(@PathVariable Long id) {
        return loanRepository.findById(id).orElseThrow();
    }
}
