package main

// Flutterwave checks the verif-hash header against our secret.
func routes(r *gin.Engine) {
	r.POST("/webhook/flutterwave", hook)
}

func hook(c *gin.Context) {
	if subtle.ConstantTimeCompare([]byte(c.GetHeader("verif-hash")), secret) != 1 {
		c.Status(401)
	}
}
