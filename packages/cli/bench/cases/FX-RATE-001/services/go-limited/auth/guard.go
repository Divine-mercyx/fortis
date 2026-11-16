package auth

type WalletGuard struct{ limiter *rate.Limiter }

func (g *WalletGuard) Allow(key string) error {
	if !g.limiter.Allow() {
		return ErrTooMany
	}
	return nil
}
