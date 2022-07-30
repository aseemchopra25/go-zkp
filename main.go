package main

import (
	"fmt"
	"time"

	"github.com/aseemchopra25/go-zkp/keygen"
	"github.com/aseemchopra25/go-zkp/proof"
)

func main() {

	keygen.Keygen() // 1. Generate Key
	// Benchmarking timings
	start := time.Now()
	for i := 0; i < 100000; i++ {
		proof.CreateProof() // 2. Create Proof
		proof.VerifyProof() // 3. Verify Proof
	}
	fmt.Println("")
	fmt.Println("Time of execution")
	fmt.Println(time.Since(start))
}
