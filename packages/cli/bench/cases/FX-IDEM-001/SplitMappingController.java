@RestController
public class SplitMappingController {
    @PostMapping(value = "/withdraw", // @hit
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public void withdraw() {}

    @RequestMapping( // @hit
            value = "/transfers",
            method = RequestMethod.POST)
    public void transfer() {}

    @RequestMapping(
            value = "/transfers",
            method = RequestMethod.GET)
    public void list() {}
}
