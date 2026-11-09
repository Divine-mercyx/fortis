// Paystack events
[ApiController]
public class HooksController : ControllerBase
{
    [HttpPost("webhooks/paystack")] // @hit
    public IActionResult Paystack(PaystackEvent body) => Ok();

    [HttpPost("api/flutterwave/webhook")] // @hit
    public IActionResult Flutterwave(FlutterwaveEvent body) => Ok();

    [HttpGet("webhooks/paystack")]
    public IActionResult Health() => Ok();
}
