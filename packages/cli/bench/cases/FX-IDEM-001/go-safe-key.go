package main

// Each request carries an Idempotency-Key header.
func routes(r *gin.Engine) {
	r.POST("/transfers", transfer)
}
