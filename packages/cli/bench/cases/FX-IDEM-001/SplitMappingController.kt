@RestController
class SplitMappingKtController {
    @PostMapping(value = ["/withdraw"], // @hit
        consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun withdraw() {}
}
