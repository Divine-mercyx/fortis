using Microsoft.AspNetCore.Mvc;

namespace PayWave.Charges
{
    [ApiController]
    public class ChargeController : ControllerBase
    {
        [HttpPost("stripe")]
        public async Task<IActionResult> Stripe([FromBody] ChargeRequest req)
        {
            var options = new PaymentIntentCreateOptions { Amount = req.Amount, Currency = "ngn" };
            return Ok(await _stripePaymentIntents.CreateAsync(options)); // @hit
        }

        [HttpPost("monnify")]
        public async Task<IActionResult> Monnify([FromBody] ChargeRequest model)
        {
            return Ok(await _monnifyClient.InitializeTransactionAsync(model.Email, model.Amount)); // @hit
        }

        [HttpPost("flutterwave")]
        public async Task<IActionResult> Flutterwave([FromBody] ChargeRequest input)
        {
            var total = input.Amount;
            return Ok(await _flutterwaveService.ChargeAsync(input.Email, total)); // @hit
        }

        [HttpPost("invoice")]
        public async Task<IActionResult> Invoice([FromBody] InvoiceRequest req)
        {
            var invoice = await _invoices.FindAsync(req.InvoiceId);
            return Ok(await _paystack.InitializeAsync(req.Email, invoice.Amount));
        }

        [HttpPost("subscription")]
        public async Task<IActionResult> Subscribe([FromBody] SubscribeRequest req)
        {
            var price = _pricing.PriceFor(req.Plan);
            return Ok(await _stripePaymentIntents.CreateAsync(Options(price)));
        }
    }
}
