[ApiController]
[Route("api/wallet")]
public class WalletAuthController(IWalletSignIn signIn) : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto) => Ok(await signIn.SignInAsync(dto));
}
