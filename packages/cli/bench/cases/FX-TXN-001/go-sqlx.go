package main

func Withdraw(id string, amount int64) error {
	var account Account
	db.Get(&account, "SELECT * FROM accounts WHERE id = $1", id)
	account.Balance -= amount // @hit
	_, err := db.Exec("UPDATE accounts SET balance = $1 WHERE id = $2", account.Balance, id)
	return err
}

func Deposit(id string, amount int64) error {
	var account Account
	db.Get(&account, "SELECT * FROM accounts WHERE id = $1", id)
	account.LedgerBalance += amount // @hit
	_, err := db.NamedExec("UPDATE accounts SET ledger_balance = :ledger_balance", account)
	return err
}
