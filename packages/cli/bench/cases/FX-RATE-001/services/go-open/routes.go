package main

func cardRoutes(r *gin.Engine, h *handlers.CardHandler) {
	r.POST("/card/login", h.Login) // @hit
}
