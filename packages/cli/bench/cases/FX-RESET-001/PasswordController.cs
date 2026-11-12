public class PasswordController : ControllerBase
{
    [HttpPost("password/forgot")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotDto dto)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
        if (user == null) return NotFound("User not found"); // @hit
        var code = new Random().Next(100000, 999999).ToString(); // @hit
        var link = $"https://{Request.Host}/reset?code={code}"; // @hit
        _logger.LogInformation("Reset code {code}", code); // @hit
        return Ok(new { sent = true, code }); // @hit
    }

    [HttpPost("password/reset")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetDto dto) // @hit
    {
        var row = await _db.Resets.FirstAsync(r => r.Token == dto.Token);
        await _users.SetPassword(row.UserId, dto.NewPassword);
        return Ok();
    }

    [HttpPost("pin/reset")]
    public async Task<IActionResult> ResetPin([FromBody] ResetPinDto dto)
    {
        var row = await _db.PinResets.FirstAsync(r => r.Code == dto.Code && r.ExpiresAt > DateTime.UtcNow);
        await _wallets.SetPin(row.UserId, BCrypt.HashPassword(dto.NewPin));
        _db.PinResets.Remove(row);
        return Ok();
    }
}
