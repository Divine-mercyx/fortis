// Monnify and Interswitch events
app.MapPost("/monnify/webhook", (MonnifyEvent body) => Results.Ok()); // @hit
app.MapPost("/webhooks/interswitch", (JsonDocument body) => Results.Ok()); // @hit
app.MapPost("/kora/webhook", (JsonDocument body) => Results.Ok()); // @hit
