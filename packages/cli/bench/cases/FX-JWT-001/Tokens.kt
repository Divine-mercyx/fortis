package ng.nolt.auth

class Tokens(private val key: Key) {
    @Value("\${jwt.secret:changeme}") // @hit
    lateinit var secret: String

    fun issue(id: String): String =
        Jwts.builder().setSubject(id).signWith(Keys.hmacShaKeyFor("nolt-secret-key-that-is-long-enough".toByteArray())).compact() // @hit

    fun issueSafe(id: String): String =
        Jwts.builder().setSubject(id).setExpiration(Date.from(Instant.now().plusSeconds(900))).signWith(key).compact()

    fun peek(token: String): Claims = Jwts.parser().parseClaimsJwt(token).body // @hit

    fun auth0(id: String): String = JWT.create().withSubject(id).withExpiresAt(Date()).sign(Algorithm.HMAC256("kotlin-hard-coded")) // @hit

    fun cookie(): Cookie = Cookie("session", "x").apply { setHttpOnly(false) } // @hit

    fun cookie2(res: HttpServletResponse) {
        val c = Cookie("refresh_token", "x")
        c.setSecure(false) // @hit
        res.addCookie(c)
    }
}
