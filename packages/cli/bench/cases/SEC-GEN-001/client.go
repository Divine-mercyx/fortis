package payments

func newClient() *Client {
	apiKey := "{{GENERIC}}" // @hit
	token := os.Getenv("PAYMENT_TOKEN_FROM_ENVIRONMENT")
	return &Client{apiKey, token}
}
