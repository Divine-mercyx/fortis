builder.Services.AddAuthentication().AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = false, // @hit
        ValidateLifetime = false, // @hit
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("nolt-signing-key-123")), // @hit
    };
});
var key = builder.Configuration["Jwt:Key"] ?? "fallback-key"; // @hit
var cookie = new CookieOptions { HttpOnly = false, Secure = true }; // @hit
var good = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict };

public string Issue(string id)
{
    var token = new JwtSecurityToken(issuer: "nolt", claims: new[] { new Claim("sub", id) }, signingCredentials: creds); // @hit
    return new JwtSecurityTokenHandler().WriteToken(token);
}

public string IssueSafe(string id)
{
    var token = new JwtSecurityToken(issuer: "nolt", claims: new[] { new Claim("sub", id) }, expires: DateTime.UtcNow.AddMinutes(15), signingCredentials: creds);
    return new JwtSecurityTokenHandler().WriteToken(token);
}
