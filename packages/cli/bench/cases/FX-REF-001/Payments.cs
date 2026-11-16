using System;
using System.Security.Cryptography;

namespace PayWave.Payments
{
    public class PaymentService
    {
        public void Pay(Order order)
        {
            var reference = $"TXN{DateTime.Now.Ticks}"; // @hit
            var txRef = "PAY-" + new Random().Next(999999); // @hit
            string paymentReference = "PW" + DateTime.UtcNow.ToString("yyyyMMddHHmmss"); // @hit
            var charge = new ChargeRequest { Reference = "ORD" + Random.Shared.Next() }; // @hit
            var safeRef = $"TXN-{Guid.NewGuid()}";
            var secureRef = "TXN" + RandomNumberGenerator.GetInt32(1000000);
            var existing = order.Reference;
            var createdAt = DateTime.UtcNow;
            var requestId = $"REQ{DateTime.Now.Ticks}";
            if (reference == null) return;
        }
    }
}
