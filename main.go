package main

import (
	"github.com/aseemchopra25/go-zkp/keygen"
	"github.com/aseemchopra25/go-zkp/proof"
)

func main() {

	keygen.Keygen()     // 1. Generate Key
	proof.CreateProof() // 2. Create Proof
	proof.VerifyProof() // 3. Verify Proof
}
