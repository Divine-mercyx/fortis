[Authorize(Policy = Policies.CanModifyServerSettings)]
public class ServerUsersController : Controller
{
    // Staff set a customer's password: no token, and saying "not found" to staff leaks nothing.
    [HttpPost("server/users/{userId}/reset-password")]
    public async Task<IActionResult> ResetUserPassword(string userId, ResetUserPasswordFromAdmin model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null || user.Id != userId)
            return NotFound();
        await _userManager.ResetPasswordAsync(user, await _userManager.GeneratePasswordResetTokenAsync(user), model.Password);
        return RedirectToAction(nameof(ListUsers));
    }
}

public class AccountController : Controller
{
    [HttpPost("account/forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
            return NotFound("No account uses that email"); // @hit
        await _emails.SendReset(user);
        return Ok();
    }
}
