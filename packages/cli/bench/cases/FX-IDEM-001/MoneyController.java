@RestController
public class MoneyController {
    @PostMapping("/transfers") // @hit
    public void transfer() {}

    @PostMapping("/wallets/{id}/withdraw") // @hit
    public void withdraw() {}

    @PutMapping("/payouts/{id}") // @hit
    public void payout() {}

    @PostMapping(value = "/loans/disbursements") // @hit
    public void disburse() {}

    @PostMapping(path = "/send-money") // @hit
    public void send() {}

    @RequestMapping(value = "/v1/transfers", method = RequestMethod.POST) // @hit
    public void v1() {}

    @PostMapping("/transfers/quote")
    public void quote() {}

    @PostMapping("/payouts/name-enquiry")
    public void enquiry() {}

    @GetMapping("/transfers")
    public void list() {}

    @PostMapping("/stores/{id}/payout-processors")
    public void settings() {}

    @RequestMapping(value = "/transfers/all", method = RequestMethod.GET)
    public void all() {}
}
