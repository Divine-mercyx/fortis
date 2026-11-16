public class CardSignIn : ICardSignIn
{
    private readonly ILogger<CardSignIn> _log;
    public async Task<TokenDto> SignInAsync(LoginDto dto)
    {
        _log.LogInformation("sign-in");
        return await IssueAsync(dto);
    }
}
