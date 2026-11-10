public class OtpService
{
    public string MakeOtp() => RandomNumberGenerator.GetInt32(100000, 999999).ToString();

    public IActionResult Send()
    {
        _logger.LogInformation("otp sent");
        return Ok(new { sent = true });
    }
}
