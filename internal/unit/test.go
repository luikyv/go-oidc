package unit

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func GetTestPrivateRsaJwk() jose.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "rsa_key",
		Algorithm: string(jose.RS256),
		Use:       string(constants.KeySigningUsage),
	}
}
