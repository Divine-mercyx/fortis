package handlers

type CardHandler struct{ svc *auth.CardService }

func (h *CardHandler) Login(c *gin.Context) {
	token, err := h.svc.SignIn(c.PostForm("email"), c.PostForm("password"))
	if err != nil {
		c.JSON(401, nil)
		return
	}
	c.JSON(200, token)
}
