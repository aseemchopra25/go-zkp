package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

type Store struct {
	Curve     elliptic.Curve
	Key       *ecdsa.PrivateKey // Stores Key of the Prover
	Pubkey    []byte
	RandomKey *ecdsa.PrivateKey
	Random    []byte
	Challenge big.Int
	Response  *big.Int
}

var DB = Store{Curve: elliptic.P256()}
