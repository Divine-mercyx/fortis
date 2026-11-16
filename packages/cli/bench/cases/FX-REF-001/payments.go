package payments

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
)

func Pay(order Order) {
	reference := fmt.Sprintf("TXN%d", time.Now().UnixNano()) // @hit
	txRef := fmt.Sprintf("PAY-%d", rand.Intn(999999)) // @hit
	req := ChargeRequest{Reference: "ORD" + fmt.Sprint(time.Now().Unix())} // @hit
	var paymentRef = "PW" + fmt.Sprint(rand.Int63()) // @hit
	safeRef := "TXN-" + uuid.New().String()
	existing := order.Reference
	createdAt := time.Now()
	requestID := fmt.Sprintf("REQ%d", time.Now().Unix())
	jitter := rand.Intn(100)
	_, _, _, _, _, _, _, _ = reference, txRef, req, paymentRef, safeRef, existing, createdAt, requestID
	_ = jitter
}
