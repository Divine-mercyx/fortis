@RestController
public class SafeLedgerController {
    @GetMapping("/ledgers/{id}")
    public Ledger get(@PathVariable String id) {
        return ledgerService.findLedgerById(id).orElseThrow();
    }

    @GetMapping("/charts/{id}")
    public ChartOfAccount chart(@PathVariable String id) {
        return chartOfAccountService.findChartOfAccountsById(id).orElseThrow();
    }
}
