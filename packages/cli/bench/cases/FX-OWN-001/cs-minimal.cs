var app = builder.Build();

app.MapGet("/wallets/{id}", async (Guid id, AppDb db) =>
{
    var wallet = await db.Wallets.FindAsync(id); // @hit
    return Results.Ok(wallet);
});

app.MapGet("/payments/{id}", async (Guid id, AppDb db) => await db.Payments.FirstAsync(p => p.Id == id)); // @hit

app.MapGet("/transfers/{id}", async (Guid id, AppDb db) =>
{
    return Results.Ok(await db.Transfers.Where(t => t.Id == id).ToListAsync()); // @hit
});
