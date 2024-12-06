package clientutil

import (
	"fmt"
	"strings"

	"github.com/luikyv/go-oidc/internal/oidc"
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

func JWKByKeyID(ctx oidc.Context, c *goidc.Client, keyID string) (goidc.JSONWebKey, error) {
	jwks, err := c.FetchPublicJWKS(ctx.HTTPClient())
	if err != nil {
		return goidc.JSONWebKey{},
			fmt.Errorf("could not find the jwk by key id: %w", err)
	}

	key, err := jwks.Key(keyID)
	if err != nil {
		return goidc.JSONWebKey{}, err
	}
	return key, nil
}

// JWKByAlg returns a client JWK based on the algorithm.
func JWKByAlg(ctx oidc.Context, c *goidc.Client, alg string) (goidc.JSONWebKey, error) {
	jwks, err := c.FetchPublicJWKS(ctx.HTTPClient())
	if err != nil {
		return goidc.JSONWebKey{},
			fmt.Errorf("could not find the jwk by algorithm: %w", err)
	}

	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			return jwk, nil
		}
	}

	return goidc.JSONWebKey{}, fmt.Errorf("invalid key algorithm: %s", alg)
}
