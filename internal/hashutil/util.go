package hashutil

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/bcrypt"
)

// Thumbprint generates a base64 URL-encoded SHA-256 hash (thumbprint) of a
// given string.
func Thumbprint(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// TODO: Move this.
func BCryptHash(s string) string {
	hashedS, err := bcrypt.GenerateFromPassword(
		[]byte(s),
		bcrypt.DefaultCost,
	)
	if err != nil {
		panic(err)
	}
	return string(hashedS)
}

func HalfHash(claim string, alg jose.SignatureAlgorithm) string {
	var hash hash.Hash
	switch alg {
	case jose.RS384, jose.ES384, jose.PS384, jose.HS384:
		hash = sha512.New384()
	case jose.RS512, jose.ES512, jose.PS512, jose.HS512:
		hash = sha512.New()
	default:
		hash = sha256.New()
	}

	hash.Write([]byte(claim))
	halfHashedClaim := hash.Sum(nil)[:hash.Size()/2]
	return base64.RawURLEncoding.EncodeToString(halfHashedClaim)
}
