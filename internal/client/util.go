package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func AuthnMethods(ctx oidc.Context, meta *goidc.ClientMeta) []goidc.ClientAuthnType {
	authnMethods := []goidc.ClientAuthnType{meta.TokenAuthnMethod}
	if ctx.TokenIntrospectionIsEnabled {
		authnMethods = append(authnMethods, meta.TokenIntrospectionAuthnMethod)
	}
	if ctx.TokenRevocationIsEnabled {
		authnMethods = append(authnMethods, meta.TokenRevocationAuthnMethod)
	}
	return authnMethods
}

func AreScopesAllowed(ctx oidc.Context, c *goidc.Client, requestedScopes string) bool {
	if requestedScopes == "" {
		return true
	}

	// Filter the client scopes that are available.
	var clientScopes []goidc.Scope
	for _, scope := range ctx.Scopes {
		if strings.Contains(c.ScopeIDs, scope.ID) {
			clientScopes = append(clientScopes, scope)
		}
	}

	// For each scope requested, make sure it matches one of the available client scopes.
	for requestedScope := range strings.SplitSeq(requestedScopes, " ") {
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
	jwks, err := JWKS(ctx, c)
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
	jwks, err := JWKS(ctx, c)
	if err != nil {
		return goidc.JSONWebKey{}, fmt.Errorf("could not find the jwk by algorithm: %w", err)
	}

	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			return jwk, nil
		}
	}

	return goidc.JSONWebKey{}, fmt.Errorf("invalid key algorithm: %s", alg)
}

// JWKS fetches the client public JWKS using the following priority:
//  1. Directly from the jwks attribute if present.
//  2. From signed_jwks_uri for federated clients (verified using the client's
//     entity configuration keys).
//  3. From jwks_uri as a fallback.
//
// It also caches the keys if they are fetched.
// TODO: Make sure the order is signed_jwks_uri, jwks_uri, jwks. Caching problem.
func JWKS(ctx oidc.Context, c *goidc.Client) (*goidc.JSONWebKeySet, error) {
	if c.JWKS != nil {
		return c.JWKS, nil
	}

	if c.IsFederated && c.SignedJWKSURI != "" {
		jwks, err := fetchSignedJWKS(ctx, c)
		if err != nil {
			return nil, err
		}
		// Cache the client JWKS.
		c.JWKS = jwks
		return jwks, nil
	}

	if c.JWKSURI == "" {
		return nil, errors.New("the client jwks was informed neither by value nor by reference")
	}

	jwks, err := fetchJWKS(ctx, c)
	if err != nil {
		return nil, err
	}

	// Cache the client JWKS.
	c.JWKS = jwks
	return jwks, err
}

func fetchJWKS(ctx oidc.Context, c *goidc.Client) (*goidc.JSONWebKeySet, error) {
	resp, err := ctx.HTTPClient().Get(c.JWKSURI)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "could not fetch the client jwks", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, fmt.Sprintf("fetching the client jwks resulted in %d", resp.StatusCode), err)
	}

	var jwks goidc.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "could not parse the client jwks", err)
	}

	return &jwks, nil
}

func fetchSignedJWKS(ctx oidc.Context, c *goidc.Client) (*goidc.JSONWebKeySet, error) {
	// Fetch the client's entity configuration to get the verification keys.
	entityJWKS, err := ctx.OpenIDFedEntityJWKS(c.ID)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "could not fetch the client entity jwks", err)
	}

	// Fetch the signed JWKS.
	resp, err := ctx.HTTPClient().Get(c.SignedJWKSURI)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "could not fetch the client signed jwks", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, fmt.Sprintf("fetching the client signed jwks resulted in %d", resp.StatusCode))
	}

	signedJWKS, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "could not read the client signed jwks", err)
	}

	// Parse and verify the signed JWKS using the entity configuration's keys.
	parsedJWT, err := jwt.ParseSigned(string(signedJWKS), ctx.OpenIDFedEntityStatementSigAlgs)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "could not parse the client signed jwks", err)
	}

	var jwks goidc.JSONWebKeySet
	if err := parsedJWT.Claims(entityJWKS.ToJOSE(), &jwks); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid signed jwks signature", err)
	}

	return &jwks, nil
}
