public class LedgerService
{
    public void Reverse(Merchant merchant, decimal amount)
    {
        merchant.PendingBalance -= amount; // @hit
        merchant.SettlementBalance = merchant.SettlementBalance + amount; // @hit
        _db.Update(merchant);
        _db.SaveChanges();
    }
}
