// Interswitch events
@RestController
@RequestMapping("/webhooks/interswitch")
public class ClassRouteController {
    @PostMapping // @hit
    public void receive(@RequestBody String body) {}

    @GetMapping
    public void health() {}
}
