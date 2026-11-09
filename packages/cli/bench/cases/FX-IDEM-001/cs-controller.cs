[ApiController]
[Route("api/[controller]")]
public class TransfersController : ControllerBase
{
    [HttpPost] // @hit
    public IActionResult Create(TransferRequest body) => Ok();

    [HttpPut("{id}")] // @hit
    public IActionResult Replace(Guid id) => Ok();

    [HttpPost("quote")]
    public IActionResult Quote() => Ok();

    [HttpGet]
    public IActionResult List() => Ok();
}
