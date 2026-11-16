[ApiController]
[Route("api/card")]
public class CardAuthController(ICardSignIn signIn) : ControllerBase
{
    [HttpPost("login")] // @hit
    public async Task<IActionResult> Login(LoginDto dto) => Ok(await signIn.SignInAsync(dto));
}
