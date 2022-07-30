package proof

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/aseemchopra25/go-zkp/db"
)

func concat(buffers ...[]byte) []byte {
	var buffer []byte
	for _, b := range buffers {
		buffer = append(buffer, b...)
	}
	return buffer
}

func CreateProof() {

	// Proof:
	// 1. Response using Rivet Shamir Transformation: (Random - PrivateKey x Challenge) mod BasePoint
	// where Challenge = sha256sum(concat(BasePoint's Xcoordinate, Random and Public Key of Prover ))

	// 2. Pubkey of Prover
	// 3. Random

	db.DB.RandomKey, _ = ecdsa.GenerateKey(db.DB.Curve, rand.Reader)
	db.DB.Random = db.DB.RandomKey.PublicKey.X.Bytes()
	db.DB.Pubkey = db.DB.Key.PublicKey.X.Bytes()

	// Challenge
	cbytes := sha256.Sum256(concat(db.DB.Curve.Params().Gx.Bytes(), db.DB.Random, db.DB.Pubkey))
	db.DB.Challenge.SetBytes((cbytes[:]))

	// Response
	r := new(big.Int)
	r.Mul(db.DB.Key.D, &db.DB.Challenge)
	r.Sub(db.DB.RandomKey.D, r)
	r.Mod(r, db.DB.Curve.Params().N)
	db.DB.Response = r
}

func VerifyProof() {
	// Check if X and Y coordinates of Public key given lie on Curve P256
	if !db.DB.Curve.IsOnCurve(db.DB.Key.X, db.DB.Key.Y) {
		fmt.Println("Verification Failed!")
	} else {
		fmt.Println("Pass!")
	}

}
