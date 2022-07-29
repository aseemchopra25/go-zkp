package db

import "crypto/ecdsa"

type Store struct {
	Key *ecdsa.PrivateKey // Stores Key of the Prover
}

var DB = Store{}
