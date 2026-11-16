using System.ComponentModel.DataAnnotations.Schema;

namespace PayWave.Cards
{
    [Table("cards")]
    public class SavedCard
    {
        public int Id { get; set; }
        public string CardNumber { get; set; } // @hit
        public string Cvv { get; set; } // @hit
        public string Last4 { get; set; }
        public string Brand { get; set; }
        public string AuthorizationCode { get; set; }
    }

    public class CardService
    {
        private readonly ILogger<CardService> _logger;

        public void Charge(ChargeRequest request)
        {
            _logger.LogInformation("Charging card {Card}", request.CardNumber); // @hit
            _logger.LogDebug($"cvv {request.Cvv}"); // @hit
            Console.WriteLine("pan " + card.Pan); // @hit
            _logger.LogInformation("Charging card ending {Last4}", request.CardNumber.Substring(12));
            _logger.LogInformation("Card brand {Brand}", request.Brand);
            _logger.LogInformation("Has cvv {HasCvv}", string.IsNullOrEmpty(request.Cvv));
            _logger.LogWarning("Declined: {Message}", response.Message);
            var number = request.CardNumber;
        }
    }
}
