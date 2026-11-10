public class HooksController : ControllerBase
{
    [HttpPost("webhooks/github")]
    public IActionResult Github() => Ok();
}
