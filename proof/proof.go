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

	// Challenge: This is required for verification checks; by GxR + AxC <----here
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
	if db.DB.Curve.IsOnCurve(db.DB.Key.X, db.DB.Key.Y) {
		fmt.Println("Public Key on Curve!")
	} else {
		fmt.Println("Public Key not on the Curve!")
	}

	// Recreate challenge

	cbytes := sha256.Sum256(concat(db.DB.Curve.Params().Gx.Bytes(), db.DB.Random, db.DB.Pubkey))
	c := cbytes[:]

	grx, gry := db.DB.Curve.ScalarBaseMult(db.DB.Response.Bytes())

	acx, acy := db.DB.Curve.ScalarMult(db.DB.Key.X, db.DB.Key.Y, c)
	fmt.Println("Received from Prover: ")
	t1 := db.DB.RandomKey.PublicKey.X
	fmt.Println(t1)
	fmt.Println("Verification Output:")
	t2, _ := db.DB.Curve.Add(grx, gry, acx, acy)
	fmt.Println(t2)
	fmt.Println("")
	if t2.Cmp(t1) == 0 {
		fmt.Println("Verification Successful")
	} else {
		fmt.Println("Verification Failed")
	}

}
