public class Kyc
{
    public void Verify(Customer customer, string bvn, string nin)
    {
        _logger.LogInformation("checking {Bvn}", bvn); // @hit
        _logger.LogError($"failed for {customer.Nin}"); // @hit
        Console.WriteLine($"bvn {customer.Bvn}"); // @hit
        Log.Information("nin {Nin}", nin); // @hit
        logger.LogWarning("retry {NationalId}", customer.NationalId); // @hit
        _logger.LogDebug( // @hit
            "kyc {Id} {Bvn}",
            customer.Id,
            customer.Bvn);

        _logger.LogInformation("checking bvn");
        _logger.LogInformation("has {Has}", string.IsNullOrEmpty(bvn));
        _logger.LogInformation("{Bvn}", Mask(bvn));
        _logger.LogInformation("{Id}", customer.Id);
    }
}
