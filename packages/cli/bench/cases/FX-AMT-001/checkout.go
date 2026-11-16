package checkout

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Pay(c *gin.Context) {
	var req CheckoutRequest
	_ = c.ShouldBindJSON(&req)
	res, _ := paystackClient.Initialize(req.Email, req.Amount) // @hit
	c.JSON(http.StatusOK, res)
}

func Order(w http.ResponseWriter, r *http.Request) {
	var body OrderRequest
	_ = json.NewDecoder(r.Body).Decode(&body)
	amount := body.Amount * 100
	payload, _ := json.Marshal(map[string]any{"email": body.Email, "amount": amount})
	http.Post("https://api.paystack.co/transaction/initialize", "application/json", bytes.NewReader(payload)) // @hit
}

func Plan(c *gin.Context) {
	var req PlanRequest
	_ = c.ShouldBindJSON(&req)
	plan := plans.Find(req.PlanID)
	res, _ := paystackClient.Initialize(req.Email, plan.PriceKobo)
	c.JSON(http.StatusOK, res)
}

func FundWallet(c *gin.Context) {
	var req FundRequest
	_ = c.ShouldBindJSON(&req)
	res, _ := paystackClient.Initialize(req.Email, req.Amount)
	c.JSON(http.StatusOK, res)
}
