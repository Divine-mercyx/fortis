package main

func InTransaction(id string, amount int64) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var wallet Wallet
		tx.First(&wallet, id)
		wallet.Balance -= amount
		return tx.Save(&wallet).Error
	})
}

func Atomic(id string, amount int64) {
	db.Model(&Wallet{}).Where("id = ?", id).Update("balance", gorm.Expr("balance - ?", amount))
}

func WithBegin(id string, amount int64) error {
	tx, _ := db.Begin()
	var balance int64
	balance -= amount
	_, err := tx.Exec("UPDATE accounts SET balance = $1", balance)
	return err
}

func Display(wallet Wallet, amount int64) int64 {
	wallet.Balance -= amount
	return wallet.Balance
}
