@RestController
public class SafeKeyController {
    @PostMapping("/transfers")
    public void transfer(@RequestHeader("Idempotency-Key") String key) {}
}
