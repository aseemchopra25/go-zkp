package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/aseemchopra25/go-zkp/db"
)

func Keygen() {
	curve := elliptic.P256()
	a, _ := ecdsa.GenerateKey(curve, rand.Reader) // Create EC Key
	db.DB.Key = a
}
