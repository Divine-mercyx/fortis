package auth

type WalletService struct{ guard *WalletGuard }

func (s *WalletService) SignIn(email, password string) (string, error) {
	if err := s.guard.Allow(email); err != nil {
		return "", err
	}
	return issue(email)
}
