package main

func GetAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var account Account
	err := db.Get(&account, "SELECT * FROM accounts WHERE id = $1", id) // @hit
	json.NewEncoder(w).Encode(account)
}

func GetCard(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row := db.QueryRow("SELECT number FROM cards WHERE id = $1", id) // @hit
	row.Scan(&w)
}
