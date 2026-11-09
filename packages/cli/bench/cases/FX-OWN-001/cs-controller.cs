using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class LoansController : ControllerBase
{
    [Authorize]
    [HttpGet("{id}")]
    public async Task<IActionResult> Get(Guid id)
    {
        var loan = await _db.Loans.FindAsync(id); // @hit
        return Ok(loan);
    }

    [HttpGet("{id}/statement")]
    public async Task<IActionResult> Statement(Guid id)
    {
        var loan = await _db.Loans.FirstOrDefaultAsync(l => l.Id == id); // @hit
        return Ok(loan);
    }

    [HttpDelete("{loanId}")]
    public async Task<IActionResult> Remove(Guid loanId)
    {
        var loan = _db.Loans.SingleOrDefault(l => l.Id == loanId); // @hit
        _db.Loans.Remove(loan);
        return NoContent();
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(Guid id)
    {
        var loan = await _repository.GetByIdAsync(id); // @hit
        return Ok(loan);
    }
}
