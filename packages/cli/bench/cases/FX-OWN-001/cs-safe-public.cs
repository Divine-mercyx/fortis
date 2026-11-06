public class PullPaymentController : ControllerBase
{
    // Anyone with this link may see it, on purpose.
    [AllowAnonymous]
    [HttpGet("pull-payments/{id}")]
    public async Task<IActionResult> Show(string id)
    {
        var payment = await _db.PullPayments.FindAsync(id);
        return Ok(payment);
    }
}
