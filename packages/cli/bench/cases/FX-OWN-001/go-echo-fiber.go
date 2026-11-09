package main

func GetPayment(c echo.Context) error {
	id := c.Param("id")
	var payment Payment
	db.First(&payment, id) // @hit
	return c.JSON(200, payment)
}

func GetInvoice(c *fiber.Ctx) error {
	var invoice Invoice
	db.First(&invoice, c.Params("id")) // @hit
	return c.JSON(invoice)
}
