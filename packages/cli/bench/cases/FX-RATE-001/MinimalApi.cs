var app = builder.Build();
app.MapPost("/auth/sign-in", (LoginDto dto, IAuth auth) => auth.Login(dto)); // @hit
app.MapPost("/auth/otp", (OtpDto dto, IAuth auth) => auth.VerifyOtp(dto)); // @hit
app.MapPost("/auth/pin", (PinDto dto, IAuth auth) => auth.VerifyPin(dto)).RequireRateLimiting("pin");
app.MapPost("/transfers", (TransferDto dto, ITransfers t) => t.Create(dto));
app.Run();
