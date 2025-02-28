package hashutil

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

// Thumbprint generates a base64 URL-encoded SHA-256 hash (thumbprint) of a
// given string.
func Thumbprint(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func BCryptHash(s string) string {
	hashedS, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hashedS)
}

// TODO: How to handle the none algorithm?
func HalfHash(claim string, alg goidc.SignatureAlgorithm) string {
	h := HashAlg(alg).New()
	h.Write([]byte(claim))
	halfHashedClaim := h.Sum(nil)[:h.Size()/2]
	return base64.RawURLEncoding.EncodeToString(halfHashedClaim)
}

func HashAlg(alg goidc.SignatureAlgorithm) crypto.Hash {
	switch alg {
	case goidc.RS512, goidc.ES512, goidc.PS512, goidc.HS512:
		return crypto.SHA512
	case goidc.RS384, goidc.ES384, goidc.PS384, goidc.HS384:
		return crypto.SHA384
	default:
		return crypto.SHA256
	}
}
