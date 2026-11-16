package checkout

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Stripe(c *gin.Context) {
	var req ChargeRequest
	_ = c.ShouldBindJSON(&req)
	params := &stripe.PaymentIntentParams{Amount: stripe.Int64(req.Amount)}
	pi, _ := stripeClient.PaymentIntents.New(params)
	res, _ := stripeClient.Checkout.Create(req.Amount) // @hit
	c.JSON(http.StatusOK, gin.H{"pi": pi, "res": res})
}

func Monnify(w http.ResponseWriter, r *http.Request) {
	amount := r.FormValue("amount")
	res, _ := monnifyClient.InitializeTransaction(r.FormValue("email"), amount) // @hit
	_ = res
}

func Flutterwave(c *gin.Context) {
	var payload ChargeRequest
	_ = c.ShouldBindJSON(&payload)
	total := payload.Amount * 100
	res, _ := flutterwaveClient.Charge(payload.Email, total) // @hit
	c.JSON(http.StatusOK, res)
}

func Invoice(c *gin.Context) {
	var req InvoiceRequest
	_ = c.ShouldBindJSON(&req)
	invoice := invoices.Find(req.InvoiceID)
	res, _ := paystackClient.Initialize(req.Email, invoice.Amount)
	c.JSON(http.StatusOK, res)
}

func Subscribe(c *gin.Context) {
	var req SubscribeRequest
	_ = c.ShouldBindJSON(&req)
	price := pricing.PriceFor(req.Plan)
	res, _ := stripeClient.Checkout.Create(price)
	c.JSON(http.StatusOK, res)
}
