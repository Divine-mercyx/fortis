public class WalletService
{
    public Task Debit(Guid id, decimal amount) =>
        _db.Wallets.Where(w => w.Id == id).ExecuteUpdateAsync(s => s.SetProperty(w => w.Balance, w => w.Balance - amount));
}
