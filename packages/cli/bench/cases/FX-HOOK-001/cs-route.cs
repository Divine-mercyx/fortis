// Remita notifications
[Route("remita/webhook")] // @hit
public class RemitaHookController : ControllerBase
{
    [HttpPost]
    public IActionResult Post(JsonDocument body) => Ok();
}
