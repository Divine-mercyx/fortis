package main

func routes(r *gin.Engine, e *echo.Echo, app *fiber.App, mux *http.ServeMux) {
	r.POST("/transfers", transfer) // @hit
	r.POST("/wallets/:id/withdraw", withdraw) // @hit
	r.PUT("/payouts/:id", payout) // @hit
	e.POST("/disbursements", disburse) // @hit
	app.Post("/send-money", send) // @hit
	mux.HandleFunc("POST /v1/transfers", transfer) // @hit

	r.POST("/transfers/quote", quote)
	r.POST("/payouts/name-enquiry", enquiry)
	r.GET("/transfers", list)
	r.POST("/profile", profile)
	mux.HandleFunc("/transfers/status", status)
}
