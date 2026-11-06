public class Row
{
    public decimal Running(decimal balance, decimal amount)
    {
        balance -= amount;
        return balance;
    }
}
