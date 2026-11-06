@RestController
public class SafeGuardController {
    @DedupRequests
    @PostMapping("/payouts")
    public void payout() {}
}
