[ApiController]
[Route("api/wallets")]
public class WalletsController : ControllerBase
{
    [HttpPost("{id}/withdraw")] // @hit
    public IActionResult Withdraw(Guid id) => Ok();

    [HttpPost("{id}/rename")]
    public IActionResult Rename(Guid id) => Ok();
}
