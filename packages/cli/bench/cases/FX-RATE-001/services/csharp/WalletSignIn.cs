public class WalletSignIn : IWalletSignIn
{
    private readonly IWalletLockout _lockout;
    public WalletSignIn(IWalletLockout lockout) { _lockout = lockout; }
    public async Task<TokenDto> SignInAsync(LoginDto dto)
    {
        _lockout.Hit(dto.Email);
        return await IssueAsync(dto);
    }
}

public class WalletLockout : IWalletLockout
{
    public void Hit(string key) { if (_failedAttempts.Get(key) > 5) throw new LockedOutException(); }
}
