package main

func Debit(id string, amount int64) {
	var wallet Wallet
	db.First(&wallet, id)
	wallet.Balance -= amount // @hit
	db.Save(&wallet)
}

func Credit(id string, amount int64) {
	var wallet Wallet
	db.First(&wallet, id)
	wallet.Balance = wallet.Balance + amount // @hit
	db.Save(&wallet)
}

func Settle(id string, amount decimal.Decimal) {
	var account Account
	db.First(&account, id)
	account.AvailableBalance = account.AvailableBalance.Sub(amount) // @hit
	db.Updates(&account)
}
