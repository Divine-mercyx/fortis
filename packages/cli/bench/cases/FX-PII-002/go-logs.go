package main

func verify(customer Customer, bvn string, nin string) {
	log.Printf("checking %s", bvn) // @hit
	log.Println("nin", customer.NIN) // @hit
	fmt.Printf("bvn %s\n", customer.BVN) // @hit
	logger.Info("lookup", zap.String("bvn", bvn)) // @hit
	slog.Error("failed", "nin", nin) // @hit
	sugar.Infow("kyc", // @hit
		"customer", customer.ID,
		"nationalId", customer.NationalID,
	)
	log.Println("checking bvn")
	logger.Info("lookup", zap.Bool("hasBvn", len(bvn) == 11))
	logger.Info("lookup", zap.String("bvn", mask(bvn)))
	log.Printf("id %s", customer.ID)
}
