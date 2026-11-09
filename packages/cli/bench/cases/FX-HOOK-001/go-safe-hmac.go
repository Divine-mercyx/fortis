package main

func routes(r *gin.Engine) {
	r.POST("/webhooks/paystack", paystackHook)
}

func paystackHook(c *gin.Context) {
	mac := hmac.New(sha512.New, secret)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), signature) {
		c.Status(401)
	}
}
