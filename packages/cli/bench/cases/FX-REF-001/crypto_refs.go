package payments

import (
	"crypto/rand"
	"math/big"
)

func NewReference(order Order) string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
	reference := "TXN" + n.String()
	return reference
}
