// Each request carries an Idempotency-Key header.
app.MapPost("/transfers", (TransferRequest body) => Results.Ok());
