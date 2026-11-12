package api

func Routes(mux *chi.Mux, h *Handler) {
	mux.Post("/login", h.Login) // @hit
	mux.With(httprate.LimitByIP(5, time.Minute)).Post("/pin/verify", h.VerifyPin)
	mux.Post("/accounts", h.Open)
}
