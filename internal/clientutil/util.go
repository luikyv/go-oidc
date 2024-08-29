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
		if strings.Contains(c.ScopeIDs, scope.ID) {
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

func JWKByKeyID(c *goidc.Client, keyID string) (jose.JSONWebKey, error) {
	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		return jose.JSONWebKey{},
			fmt.Errorf("could not find the jwk by key id: %w", err)
	}

	keys := jwks.Key(keyID)
	if len(keys) == 0 {
		return jose.JSONWebKey{}, errors.New("invalid key ID")
	}

	return keys[0], nil
}

// JWKByAlg returns a client JWK based on the algorithm.
func JWKByAlg(c *goidc.Client, alg string) (jose.JSONWebKey, error) {
	jwks, err := c.FetchPublicJWKS()
	if err != nil {
		return jose.JSONWebKey{},
			fmt.Errorf("could not find the jwk by algorithm: %w", err)
	}

	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			return jwk, nil
		}
	}

	return jose.JSONWebKey{}, fmt.Errorf("invalid key algorithm: %s", alg)
}
