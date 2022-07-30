package keygen

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/aseemchopra25/go-zkp/db"
)

func Keygen() {
	a, _ := ecdsa.GenerateKey(db.DB.Curve, rand.Reader) // Create EC Key
	db.DB.Key = a
	db.DB.Pubkey = db.DB.Key.PublicKey.X.Bytes()
	// a.Params()
}
