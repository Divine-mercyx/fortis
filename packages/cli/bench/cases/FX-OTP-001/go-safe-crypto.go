package main

import (
	"crypto/rand"
	"math/big"
)

func makeOtp() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return n.String()
}

func respond(c *gin.Context) {
	c.JSON(200, gin.H{"sent": true})
}
