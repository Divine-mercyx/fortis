package main

func routes(r *gin.Engine) {
	r.POST("/webhooks/github", githubHook)
}
