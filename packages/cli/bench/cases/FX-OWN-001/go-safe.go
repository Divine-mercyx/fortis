package main

func OwnLoan(c *gin.Context) {
	id := c.Param("id")
	var loan Loan
	db.Where("id = ? AND user_id = ?", id, c.GetString("userID")).First(&loan)
	c.JSON(200, loan)
}

func OwnAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var account Account
	db.Get(&account, "SELECT * FROM accounts WHERE id = $1 AND owner = $2", id, owner(r))
}

func Profile(c *gin.Context) {
	id := c.Param("id")
	var profile Profile
	db.First(&profile, id)
}

func loadLoan(id string) Loan {
	var loan Loan
	db.First(&loan, id)
	return loan
}

func ListLoans(c *gin.Context) {
	var loans []Loan
	db.Find(&loans)
	c.JSON(200, loans)
}
