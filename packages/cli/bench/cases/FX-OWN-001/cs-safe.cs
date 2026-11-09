[ApiController]
public class WalletsController : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<IActionResult> Owned(Guid id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var wallet = await _db.Wallets.FirstOrDefaultAsync(w => w.Id == id && w.UserId == userId);
        return Ok(wallet);
    }

    [HttpGet("{id}/details")]
    public async Task<IActionResult> Checked(Guid id)
    {
        var wallet = await _db.Wallets.FindAsync(id);
        var result = await _authorization.AuthorizeAsync(User, wallet, "Owner");
        return result.Succeeded ? Ok(wallet) : Forbid();
    }

    [HttpGet("settings/{id}")]
    public async Task<IActionResult> Settings(Guid id)
    {
        var settings = await _db.Settings.FindAsync(id);
        return Ok(settings);
    }

    private Wallet Load(Guid id)
    {
        return _db.Wallets.Find(id);
    }
}
