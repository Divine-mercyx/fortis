package wallet

import (
	"strconv"

	"github.com/shopspring/decimal"
)

type Wallet struct {
	ID               uint
	Balance          float64 `json:"balance"` // @hit
	AvailableBalance *float64 // @hit
	Fee              float32 // @hit
	LedgerBalance    decimal.Decimal
	BalanceKobo      int64
	InterestRate     float64
	Latitude         float64
	AmountLabel      string
}

func Send(amount float64, account string) error {
	return nil
}

func Total(subtotal, fee decimal.Decimal) decimal.Decimal {
	return subtotal.Add(fee)
}

func Parse(req TransferRequest) {
	amount, _ := strconv.ParseFloat(req.Amount, 64) // @hit
	total := float64(req.Total)
	ratio, _ := strconv.ParseFloat(req.Ratio, 64)
	kobo := int64(float64(req.Amount) * 100)
	count, _ := strconv.Atoi(req.Count)
	_ = amount
	_ = total
	_ = ratio
	_ = kobo
	_ = count
}

func Score(weight float64) float64 { return weight * 2 }

func Convert(
	amount float64,
	rate float64,
) float64 {
	return amount * rate
}
