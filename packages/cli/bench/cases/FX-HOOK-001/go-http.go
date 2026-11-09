package main

// Remita notifications
func routes(mux *http.ServeMux, app *fiber.App, e *echo.Echo) {
	mux.HandleFunc("POST /remita/webhook", remitaHook) // @hit
	mux.HandleFunc("/kora/webhook", koraHook) // @hit
	app.Post("/opay/webhook", opayHook) // @hit
	e.POST("/interswitch/webhook", interswitchHook) // @hit
}
