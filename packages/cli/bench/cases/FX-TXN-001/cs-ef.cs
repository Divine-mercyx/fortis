public class WalletService
{
    public async Task Debit(Guid id, decimal amount)
    {
        var wallet = await _db.Wallets.FindAsync(id);
        wallet.Balance -= amount; // @hit
        await _db.SaveChangesAsync();
    }

    public async Task Credit(Guid id, decimal amount)
    {
        var wallet = await _db.Wallets.FindAsync(id);
        wallet.Balance = wallet.Balance + amount; // @hit
        await _db.SaveChangesAsync();
    }

    public void Settle(Account account, decimal amount)
    {
        account.AvailableBalance += amount; // @hit
        _db.SaveChanges();
    }
}
