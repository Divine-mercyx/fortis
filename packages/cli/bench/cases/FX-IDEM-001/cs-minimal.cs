app.MapPost("/payouts", (PayoutRequest body) => Results.Ok()); // @hit
app.MapPost("/send-money", (SendRequest body) => Results.Ok()); // @hit
app.MapPut("/disbursements/{id}", (Guid id) => Results.Ok()); // @hit
app.MapPost("/transfers/validate", (ValidateRequest body) => Results.Ok());
app.MapPost("/profile", (ProfileRequest body) => Results.Ok());
