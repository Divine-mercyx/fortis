[Authorize(Policy = Policies.CanModifyServerSettings, AuthenticationSchemes = AuthenticationSchemes.Cookie)]
public partial class ServerUsersController : Controller
{
    [HttpPost("server/users/{userId}/reset-password")]
    public async Task<IActionResult> ResetUserPassword(string userId, ResetUserPasswordFromAdmin model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null || user.Id != userId)
            return NotFound();
        await _userManager.ResetPasswordAsync(user, await _userManager.GeneratePasswordResetTokenAsync(user), model.Password);
        return RedirectToAction(nameof(ListUsers));
    }

    [AllowAnonymous]
    [HttpPost("server/login")] // @hit
    public async Task<IActionResult> Login(LoginModel model)
    {
        return Ok(await _signIn.PasswordSignInAsync(model.Email, model.Password, false, false));
    }
}

[ApiController]
[Route("api/admin/customers")]
public class CustomerSupportController : ControllerBase
{
    [HttpPost("{id}/pin/reset")]
    public IActionResult ResetPin(string id) => Ok(_pins.Reset(id));
}
