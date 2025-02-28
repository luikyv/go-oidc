package goidc

import (
	"context"
	"crypto"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type SignatureAlgorithm = jose.SignatureAlgorithm

const (
	None  SignatureAlgorithm = "none"
	HS256 SignatureAlgorithm = jose.HS256
	HS384 SignatureAlgorithm = jose.HS384
	HS512 SignatureAlgorithm = jose.HS512
	RS256 SignatureAlgorithm = jose.RS256
	RS384 SignatureAlgorithm = jose.RS384
	RS512 SignatureAlgorithm = jose.RS512
	ES256 SignatureAlgorithm = jose.ES256
	ES384 SignatureAlgorithm = jose.ES384
	ES512 SignatureAlgorithm = jose.ES512
	PS256 SignatureAlgorithm = jose.PS256
	PS384 SignatureAlgorithm = jose.PS384
	PS512 SignatureAlgorithm = jose.PS512
)

type KeyEncryptionAlgorithm = jose.KeyAlgorithm

const (
	RSA1_5       KeyEncryptionAlgorithm = jose.RSA1_5
	RSA_OAEP     KeyEncryptionAlgorithm = jose.RSA_OAEP
	RSA_OAEP_256 KeyEncryptionAlgorithm = jose.RSA_OAEP_256
)

type ContentEncryptionAlgorithm = jose.ContentEncryption

const (
	A128CBC_HS256 ContentEncryptionAlgorithm = jose.A128CBC_HS256
	A192CBC_HS384 ContentEncryptionAlgorithm = jose.A192CBC_HS384
	A256CBC_HS512 ContentEncryptionAlgorithm = jose.A256CBC_HS512
	A128GCM       ContentEncryptionAlgorithm = jose.A128GCM
	A192GCM       ContentEncryptionAlgorithm = jose.A192GCM
	A256GCM       ContentEncryptionAlgorithm = jose.A256GCM
)

type JSONWebKey = jose.JSONWebKey

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

func (jwks JSONWebKeySet) Key(kid string) (JSONWebKey, error) {
	for _, key := range jwks.Keys {
		if key.KeyID == kid {
			return key, nil
		}
	}

	return JSONWebKey{}, fmt.Errorf("could not find jwk with id: %s", kid)
}

func (jwks JSONWebKeySet) Public() JSONWebKeySet {
	publicKeys := []JSONWebKey{}
	for _, jwk := range jwks.Keys {
		publicKey := jwk.Public()
		// A JWK that cannot be made public is returned as the zero value.
		if publicKey.Key != nil {
			publicKeys = append(publicKeys, publicKey)
		}
	}

	return JSONWebKeySet{Keys: publicKeys}
}

func (jwks JSONWebKeySet) KeyByAlg(alg string) (JSONWebKey, error) {
	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			return jwk, nil
		}
	}

	return JSONWebKey{}, fmt.Errorf("could not find jwk matching the algorithm %s", alg)
}

// SignerFunc defines a function type for handling signing operations.
type SignerFunc func(ctx context.Context, alg SignatureAlgorithm) (kid string, signer crypto.Signer, err error)

// DecrypterFunc defines a function type for handling decryption operations.
type DecrypterFunc func(ctx context.Context, kid string, alg KeyEncryptionAlgorithm) (crypto.Decrypter, error)
