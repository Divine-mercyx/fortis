package main

import (
	"fmt"
	"math/rand"
)

func makeOtp() string {
	otp := rand.Intn(900000) + 100000 // @hit
	return fmt.Sprint(otp)
}

func resetToken() int {
	return rand.Int63n(1 << 40) // @hit
}

func send(c *gin.Context, otp string, phone string) {
	log.Printf("otp for %s: %s", phone, otp) // @hit
	logger.Info("sent", zap.String("otp", otp)) // @hit
	c.JSON(200, gin.H{"sent": true, "otp": otp}) // @hit
}

func review() {
	log.Println("reviewer otp is 482901") // @hit
}

func retryDelay() int {
	return rand.Intn(100)
}

func notice() {
	log.Println("otp sent")
}
