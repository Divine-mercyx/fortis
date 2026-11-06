public class WalletService
{
    public async Task Debit(Guid id, decimal amount)
    {
        await using var tx = await _db.Database.BeginTransactionAsync();
        var wallet = await _db.Wallets.FindAsync(id);
        wallet.Balance -= amount;
        await _db.SaveChangesAsync();
        await tx.CommitAsync();
    }
}
