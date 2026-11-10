public class OtpService
{
    public string MakeOtp()
    {
        var otp = new Random().Next(100000, 999999); // @hit
        return otp.ToString();
    }

    public int ResetCode() => Random.Shared.Next(100000, 999999); // @hit

    public IActionResult Send(string otp, string phone)
    {
        _logger.LogInformation("otp {Otp} for {Phone}", otp, phone); // @hit
        Console.WriteLine($"otp is {otp}"); // @hit
        return Ok(new { sent = true, otp }); // @hit
    }

    public void Review()
    {
        _logger.LogInformation("reviewer otp is 482901"); // @hit
    }

    public int Delay() => new Random().Next(100);
}
