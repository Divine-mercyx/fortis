[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    [HttpPost("login")] // @hit
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        return Ok(await _auth.Login(dto));
    }

    [HttpPost("otp/verify")]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> VerifyOtp([FromBody] OtpDto dto)
    {
        return Ok(await _auth.VerifyOtp(dto));
    }

    [HttpPost("pin/verify")] // @hit
    public async Task<IActionResult> VerifyPin([FromBody] PinDto dto)
    {
        return Ok(await _pins.Verify(dto));
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        return Ok();
    }
}
