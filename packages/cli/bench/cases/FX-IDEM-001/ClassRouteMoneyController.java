@RestController
@RequestMapping("/api/transfers")
public class ClassRouteMoneyController {
    @PostMapping // @hit
    public void create() {}

    @PostMapping("/quote")
    public void quote() {}

    @GetMapping
    public void list() {}
}
