package api

func Register(r *gin.Engine, h *Handler, otp *OtpHandler) {
	r.POST("/auth/login", h.Login) // @hit
	r.POST("/auth/sign-in/phone", h.LoginWithPhone) // @hit
	r.POST("/auth/otp/verify", otp.Verify) // @hit
	r.POST("/wallet/pin/verify", h.VerifyPin) // @hit
	r.POST("/auth/2fa", h.VerifyTotp) // @hit
	r.POST("/auth/password/forgot", limiter.Middleware(), h.ForgotPassword)
	r.POST("/auth/logout", h.Logout)
	r.POST("/transfers", h.Transfer)
	r.GET("/auth/login", h.LoginPage)
}
