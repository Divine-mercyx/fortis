using Microsoft.AspNetCore.Mvc;

namespace PayWave.Checkout
{
    [ApiController]
    [Route("checkout")]
    public class CheckoutController : ControllerBase
    {
        private readonly PaystackService _paystack;
        private readonly HttpClient _http;

        [HttpPost("pay")]
        public async Task<IActionResult> Pay([FromBody] CheckoutRequest request)
        {
            return Ok(await _paystack.InitializeAsync(request.Email, request.Amount)); // @hit
        }

        [HttpPost("order")]
        public async Task<IActionResult> Order([FromBody] OrderRequest dto)
        {
            var amount = dto.Amount * 100;
            return Ok(await _http.PostAsJsonAsync("https://api.paystack.co/transaction/initialize", new { email = dto.Email, amount })); // @hit
        }

        [HttpPost("plan")]
        public async Task<IActionResult> Plan([FromBody] PlanRequest request)
        {
            var plan = await _plans.FindAsync(request.PlanId);
            return Ok(await _paystack.InitializeAsync(request.Email, plan.PriceKobo));
        }

        [HttpPost("donate")]
        public async Task<IActionResult> Donate([FromBody] DonationRequest request)
        {
            return Ok(await _paystack.InitializeAsync(request.Email, request.Amount));
        }
    }
}
