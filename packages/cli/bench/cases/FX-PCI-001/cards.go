package cards

import (
	"fmt"
	"log"
)

type SavedCard struct {
	ID         uint   `gorm:"primaryKey"`
	CardNumber string `gorm:"column:card_number"` // @hit
	CVV        string `gorm:"column:cvv"` // @hit
	Last4      string `gorm:"column:last4"`
	Brand      string `gorm:"column:brand"`
}

func Charge(req ChargeRequest) {
	log.Printf("charging card %s", req.CardNumber) // @hit
	fmt.Println("cvv", req.CVV) // @hit
	logger.Info("charge", zap.String("pan", card.Pan)) // @hit
	log.Printf("charging card ending %s", req.CardNumber[len(req.CardNumber)-4:])
	log.Printf("has cvv: %v", len(req.CVV) > 0)
	log.Printf("card brand %s", req.Brand)
	log.Printf("declined: %s", resp.Message)
	number := req.CardNumber
	_ = number
}
