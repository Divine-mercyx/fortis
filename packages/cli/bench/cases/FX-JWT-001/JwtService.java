package ng.nolt.auth;

public class JwtService {
    @Value("${jwt.secret:changeme}") // @hit
    private String secret;

    public String issue(String id) {
        return Jwts.builder().setSubject(id).signWith(Keys.hmacShaKeyFor("nolt-secret-key-that-is-long-enough".getBytes())).compact(); // @hit
    }

    public String issueForever(String id) {
        return Jwts.builder().setSubject(id).signWith(key).compact(); // @hit
    }

    public String issueSafe(String id) {
        return Jwts.builder().setSubject(id).setExpiration(Date.from(Instant.now().plusSeconds(900))).signWith(key).compact();
    }

    public Claims peek(String token) {
        return Jwts.parser().parseClaimsJwt(token).getBody(); // @hit
    }

    public void cookie(HttpServletResponse res, String token) {
        Cookie c = new Cookie("access_token", token);
        c.setHttpOnly(false); // @hit
        res.addCookie(c);
    }

    public String auth0(String id) {
        return JWT.create().withSubject(id).sign(Algorithm.HMAC256("auth0-hard-coded")); // @hit
    }
}
