package main

func walletRoutes(r *gin.Engine, h *handlers.WalletHandler) {
	r.POST("/wallet/login", h.Login)
}
