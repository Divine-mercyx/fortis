@RestController
@RequestMapping("/api/customers")
public class AdminController {

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/{id}/password/reset")
    public ResponseEntity<Void> resetPassword(@PathVariable Long id) {
        customers.sendReset(id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/pin/verify") // @hit
    public ResponseEntity<Void> verifyPin(@RequestBody PinRequest req) {
        pins.verify(req);
        return ResponseEntity.ok().build();
    }
}
