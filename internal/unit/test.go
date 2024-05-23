package unit

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func GetTestPrivateRs256Jwk(keyId string) jose.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Algorithm: string(jose.RS256),
		Use:       string(constants.KeySignatureUsage),
	}
}

func GetTestPrivatePs256Jwk(keyId string) jose.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Algorithm: string(jose.PS256),
		Use:       string(constants.KeySignatureUsage),
	}
}
