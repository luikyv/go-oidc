package unit

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func GetTestPrivateRs256Jwk(keyId string) goidc.JsonWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJsonWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Algorithm: string(jose.RS256),
		Use:       string(goidc.KeySignatureUsage),
	})
}

func GetTestPrivatePs256Jwk(keyId string) goidc.JsonWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJsonWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Algorithm: string(jose.PS256),
		Use:       string(goidc.KeySignatureUsage),
	})
}
