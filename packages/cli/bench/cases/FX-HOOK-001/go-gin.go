package main

// Paystack and Flutterwave events
func routes(r *gin.Engine) {
	r.POST("/webhooks/paystack", paystackHook) // @hit
	r.POST("/webhook/flutterwave", flutterwaveHook) // @hit
	r.Any("/monnify/webhook", monnifyHook) // @hit
	r.GET("/webhooks/paystack/health", health)
}
