public class SettingsController : ControllerBase
{
    [HttpPost("~/api/stores/{id}/payout-processors/onchain")]
    public IActionResult Save() => Ok();

    [HttpPost("~/api/payouts/{id}/mark-paid")]
    public IActionResult Mark() => Ok();

    [HttpPut("~/api/transfer-limits")]
    public IActionResult Limits() => Ok();
}
