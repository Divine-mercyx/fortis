package auth

type CardService struct{ store *Store }

func (s *CardService) SignIn(email, password string) (string, error) {
	if !s.store.Check(email, password) {
		return "", ErrBadLogin
	}
	return issue(email)
}
