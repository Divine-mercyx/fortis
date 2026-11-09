package main

func GetLoan(c *gin.Context) {
	var loan Loan
	db.First(&loan, c.Param("id")) // @hit
	c.JSON(200, loan)
}

func GetWallet(c *gin.Context) {
	id := c.Param("id")
	var wallet Wallet
	db.Where("id = ?", id).First(&wallet) // @hit
	c.JSON(200, wallet)
}

func GetTransfer(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var transfer Transfer
	db.First(&transfer, id) // @hit
	c.JSON(200, transfer)
}
