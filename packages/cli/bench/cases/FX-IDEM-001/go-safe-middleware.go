package main

func routes(r *gin.Engine) {
	r.POST("/transfers", dedupRequests(), transfer)
}
