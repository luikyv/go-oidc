package clientutil

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func AreScopesAllowed(
	c *goidc.Client,
	availableScopes []goidc.Scope,
	requestedScopes string,
) bool {
	if requestedScopes == "" {
		return true
	}

	// Filter the client scopes that are available.
	var clientScopes []goidc.Scope
	for _, scope := range availableScopes {
		if strings.Contains(c.Scopes, scope.ID) {
			clientScopes = append(clientScopes, scope)
		}
	}

	// For each scope requested, make sure it matches one of the available
	// client scopes.
	for _, requestedScope := range strings.Split(requestedScopes, " ") {
		matches := false
		for _, scope := range clientScopes {
			if scope.Matches(requestedScope) {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}

	return true
}

func PublicKey(c *goidc.Client, keyID string) (jose.JSONWebKey, error) {
	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	keys := jwks.Key(keyID)
	if len(keys) == 0 {
		return jose.JSONWebKey{}, errors.New("invalid key ID")
	}

	return keys[0], nil
}

func JARMEncryptionJWK(c *goidc.Client) (jose.JSONWebKey, error) {
	return encJWK(c, c.JARMKeyEncAlg)
}

func UserInfoEncryptionJWK(c *goidc.Client) (jose.JSONWebKey, error) {
	return encJWK(c, c.UserInfoKeyEncAlg)
}

func IDTokenEncryptionJWK(c *goidc.Client) (jose.JSONWebKey, error) {
	return encJWK(c, c.IDTokenKeyEncAlg)
}

// sigJWK returns the signature JWK based on the algorithm.
func sigJWK(
	c *goidc.Client,
	alg jose.SignatureAlgorithm,
) (
	jose.JSONWebKey,
	error,
) {
	jwk, err := jwkMatchingAlg(c, string(alg))
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	if jwk.Use != string(goidc.KeyUsageSignature) {
		return jose.JSONWebKey{}, errors.New("invalid key usege")
	}

	return jwk, nil
}

// encJWK returns the encryption JWK based on the algorithm.
func encJWK(
	c *goidc.Client,
	alg jose.KeyAlgorithm,
) (
	jose.JSONWebKey,
	error,
) {
	jwk, err := jwkMatchingAlg(c, string(alg))
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	if jwk.Use != string(goidc.KeyUsageEncryption) {
		return jose.JSONWebKey{}, errors.New("invalid key usege")
	}

	return jwk, nil
}

// jwkMatchingAlg returns a client JWK based on the algorithm.
func jwkMatchingAlg(c *goidc.Client, alg string) (jose.JSONWebKey, error) {
	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			return jwk, nil
		}
	}

	return jose.JSONWebKey{}, fmt.Errorf("invalid key algorithm: %s", alg)
}
