package main

func routes(r *gin.Engine) {
	r.POST("/stores/:id/payout-processors", saveProcessor)
	r.POST("/payouts/:id/mark-paid", markPaid)
	r.POST("/transfer-limits", saveLimits)
}
