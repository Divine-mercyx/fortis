// Paystack events
public class PaystackController : ControllerBase
{
    [HttpPost("webhooks/paystack")]
    public IActionResult Post()
    {
        using var hmac = new HMACSHA512(_secret);
        var match = CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(_body), _signature);
        return match ? Ok() : Unauthorized();
    }
}
