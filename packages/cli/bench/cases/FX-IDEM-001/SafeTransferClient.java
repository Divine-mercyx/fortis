@FeignClient(name = "ledger")
public interface SafeTransferClient {
    @PostMapping("/transfers")
    void transfer(@RequestBody Transfer body);
}
