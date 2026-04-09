package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Options struct {
	TrustChain []string
}

func JWKByKeyID(ctx oidc.Context, c *goidc.Client, keyID string) (goidc.JSONWebKey, error) {
	jwks, err := JWKS(ctx, c)
	if err != nil {
		return goidc.JSONWebKey{}, fmt.Errorf("could not find the jwk by key id: %w", err)
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
//  1. From signed_jwks_uri for federated clients (verified using the client's entity configuration keys).
//  2. From jwks_uri as a fallback.
//  3. Directly from the jwks attribute if present.
//
// It also caches the keys if they are fetched.
func JWKS(ctx oidc.Context, c *goidc.Client) (*goidc.JSONWebKeySet, error) {
	if jwks := c.CachedJWKS(); jwks != nil {
		return jwks, nil
	}

	if c.SignedJWKSURI != "" {
		jwks, err := fetchSignedJWKS(ctx, c)
		if err != nil {
			return nil, err
		}
		c.CacheJWKS(jwks)
		return jwks, nil
	}

	if c.JWKSURI != "" {
		jwks, err := fetchJWKS(ctx, c)
		if err != nil {
			return nil, err
		}
		c.CacheJWKS(jwks)
		return jwks, nil
	}

	if c.JWKS == nil {
		return nil, errors.New("the client jwks was informed neither by value nor by reference")
	}
	return c.JWKS, nil
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
	parsedJWT, err := jwt.ParseSigned(string(signedJWKS), ctx.OpenIDFedSigAlgs)
	if err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "could not parse the client signed jwks", err)
	}

	var jwks goidc.JSONWebKeySet
	if err := parsedJWT.Claims(entityJWKS.ToJOSE(), &jwks); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidClientMetadata, "invalid signed jwks signature", err)
	}

	return &jwks, nil
}
