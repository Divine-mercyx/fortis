package auth

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Issue(id string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": id}) // @hit
	return token.SignedString(key)
}

func IssueHardcoded(id string) (string, error) {
	claims := jwt.RegisteredClaims{Subject: id, ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute))}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("nolt-signing-secret")) // @hit
}

func Peek(raw string) jwt.MapClaims {
	claims := jwt.MapClaims{}
	jwt.NewParser().ParseUnverified(raw, claims) // @hit
	return claims
}

func Secret() string {
	secret := os.Getenv("JWT_SECRET") // @hit
	if secret == "" {
		secret = "changeme"
	}
	return secret
}

func Keyfunc(t *jwt.Token) (any, error) {
	return []byte("another-hard-coded-key"), nil // @hit
}

func Cookie(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: v, HttpOnly: false}) // @hit
}

func Safe(raw string) (*jwt.Token, error) {
	return jwt.Parse(raw, func(t *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}))
}
