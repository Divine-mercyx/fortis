@RestController
@RequestMapping("/loans")
public class LoanController {
    private final LoanRepository loanRepository;

    @GetMapping("/{id}")
    public Loan get(@PathVariable Long id) {
        return loanRepository.findById(id).orElseThrow(); // @hit
    }

    @GetMapping("/{loanId}/statement")
    public ResponseEntity<Loan> statement(@PathVariable UUID loanId) {
        Loan loan = loanRepository.getReferenceById(loanId); // @hit
        return ResponseEntity.ok(loan);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        Loan loan = loanRepository.getById(id); // @hit
        loanRepository.delete(loan);
    }

    @PutMapping("/{id}")
    public Loan update(@PathVariable Long id, @RequestBody Loan body) {
        return loanService.findById(id); // @hit
    }

    @RequestMapping(value = "/{id}/card", method = RequestMethod.GET)
    public Card card(@PathVariable Long id) {
        return cardRepository.findById(id).orElseThrow(); // @hit
    }
}
