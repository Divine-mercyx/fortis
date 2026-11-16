using System;
using System.ComponentModel.DataAnnotations;

namespace PayWave.Wallets
{
    public class Wallet
    {
        [Key] public Guid Id { get; set; }
        public double Balance { get; set; } // @hit
        public float Fee { get; set; } // @hit
        public double? AvailableBalance { get; set; } // @hit
        public decimal LedgerBalance { get; set; }
        public long BalanceKobo { get; set; }
        public double InterestRate { get; set; }
        public double BalancePercent { get; set; }
        public string AmountLabel { get; set; }
    }

    public class TransferService
    {
        public void Send(double amount, string account) { }
        public decimal Total(decimal subtotal, decimal fee) => subtotal + fee;

        public void Parse(TransferRequest request)
        {
            var amount = double.Parse(request.Amount); // @hit
            var total = Convert.ToDouble(request.Total); // @hit
            var kobo = (long)Math.Round(double.Parse(request.Amount) * 100);
            var ratio = double.Parse(request.Ratio);
            var shown = LedgerBalance.ToString("N2");
            var negative = double.Parse(request.Amount) < 0;
        }

        public double Latitude() => 6.45;
        public double Score(double weight) => weight * 2;
    }
}
