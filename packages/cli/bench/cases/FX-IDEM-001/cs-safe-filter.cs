public class PayoutsController : ControllerBase
{
    [DedupRequests]
    [HttpPost("payouts")]
    public IActionResult Create() => Ok();
}
