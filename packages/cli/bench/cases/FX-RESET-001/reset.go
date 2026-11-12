package auth

import (
	"fmt"
	"log"
	"math/rand"
)

func (h *Handler) ForgotPassword(c *gin.Context) {
	code := fmt.Sprintf("%06d", rand.Intn(1000000)) // @hit
	link := "https://" + c.Request.Host + "/reset?code=" + code // @hit
	log.Printf("reset code %s", code) // @hit
	h.mailer.Send(c.PostForm("email"), link)
	c.JSON(200, gin.H{"sent": true, "code": code}) // @hit
}

func (h *Handler) ResetPassword(c *gin.Context) { // @hit
	row := h.resets.ByToken(c.PostForm("token"))
	h.users.SetPassword(row.UserID, c.PostForm("new_password"))
	c.JSON(200, gin.H{"ok": true})
}

func ResetForm(f *Form) {
	f.Seed = rand.Intn(10)
}
