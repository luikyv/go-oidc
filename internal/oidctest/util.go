package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var (
	Scope1 = goidc.NewScope("scope1")
	Scope2 = goidc.NewScope("scope2")
)

func NewContext(t *testing.T) *oidc.Context {
	t.Helper()

	keyID := "test_server_key"
	jwk := PrivatePS256JWK(t, keyID, goidc.KeyUsageSignature)

	config := oidc.Configuration{
		Profile: goidc.ProfileOpenID,
		Host:    "https://example.com",

		ClientManager:       storage.NewClientManager(),
		AuthnSessionManager: storage.NewAuthnSessionManager(),
		GrantSessionManager: storage.NewGrantSessionManager(),

		Scopes:      []goidc.Scope{goidc.ScopeOpenID, Scope1, Scope2},
		PrivateJWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}},
		GrantTypes: []goidc.GrantType{
			goidc.GrantAuthorizationCode,
			goidc.GrantClientCredentials,
			goidc.GrantImplicit,
			goidc.GrantRefreshToken,
			goidc.GrantIntrospection,
		},
		ResponseTypes: []goidc.ResponseType{
			goidc.ResponseTypeCode,
			goidc.ResponseTypeIDToken,
			goidc.ResponseTypeToken,
			goidc.ResponseTypeCodeAndIDToken,
			goidc.ResponseTypeCodeAndToken,
			goidc.ResponseTypeIDTokenAndToken,
			goidc.ResponseTypeCodeAndIDTokenAndToken,
		},
		ResponseModes: []goidc.ResponseMode{
			goidc.ResponseModeQuery,
			goidc.ResponseModeFragment,
			goidc.ResponseModeFormPost,
		},
		TokenOptionsFunc: func(c *goidc.Client, scopes string) (goidc.TokenOptions, error) {
			return goidc.TokenOptions{
				JWTSignatureKeyID: keyID,
				LifetimeSecs:      60,
				Format:            goidc.TokenFormatJWT,
			}, nil
		},
		AuthnSessionTimeoutSecs: 60,
		ClientAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnNone,
			goidc.ClientAuthnSecretPost,
			goidc.ClientAuthnSecretBasic,
			goidc.ClientAuthnPrivateKeyJWT,
			goidc.ClientAuthnSecretJWT,
		},
		UserDefaultSigKeyID:         keyID,
		UserSigKeyIDs:               []string{keyID},
		EndpointWellKnown:           "/.well-known/openid-configuration",
		EndpointJWKS:                "/jwks",
		EndpointToken:               "/token",
		EndpointAuthorize:           "/authorize",
		EndpointPushedAuthorization: "/par",
		EndpointDCR:                 "/register",
		EndpointUserInfo:            "/userinfo",
		EndpointIntrospection:       "/introspect",
		AssertionLifetimeSecs:       600,
	}

	ctx := oidc.NewContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/auth", nil),
		config,
	)

	return ctx
}

func AuthnSessions(t *testing.T, ctx *oidc.Context) []*goidc.AuthnSession {
	t.Helper()

	sessionManager, _ := ctx.AuthnSessionManager.(*storage.AuthnSessionManager)
	sessions := make([]*goidc.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GrantSessions(t *testing.T, ctx *oidc.Context) []*goidc.GrantSession {
	t.Helper()

	manager, _ := ctx.GrantSessionManager.(*storage.GrantSessionManager)
	tokens := make([]*goidc.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		tokens = append(tokens, t)
	}

	return tokens
}

func Clients(t *testing.T, ctx *oidc.Context) []*goidc.Client {
	t.Helper()

	manager, _ := ctx.ClientManager.(*storage.ClientManager)
	clients := make([]*goidc.Client, 0, len(manager.Clients))
	for _, c := range manager.Clients {
		clients = append(clients, c)
	}

	return clients
}

func PrivateRS256JWK(
	t *testing.T,
	keyID string,
	usage goidc.KeyUsage,
) jose.JSONWebKey {
	return privateRSAJWK(t, keyID, jose.RS256, usage)
}

func PrivatePS256JWK(
	t *testing.T,
	keyID string,
	usage goidc.KeyUsage,
) jose.JSONWebKey {
	return privateRSAJWK(t, keyID, jose.PS256, usage)
}

func privateRSAJWK(
	t *testing.T,
	keyID string,
	alg jose.SignatureAlgorithm,
	usage goidc.KeyUsage,
) jose.JSONWebKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generated PS256 JWK: %v", err)
	}
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(alg),
		Use:       string(usage),
	}
}

func RawJWKS(jwk jose.JSONWebKey) []byte {
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	return jwks
}

// func SafeClaims(t *testing.T, jws string, privateJWK jose.JSONWebKey) map[string]any {
// 	parsedToken, err := jwt.ParseSigned(jws, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(privateJWK.Algorithm)})
// 	require.Nil(t, err, "invalid JWT")

// 	var claims map[string]any
// 	err = parsedToken.Claims(privateJWK.Public().Key, &claims)
// 	require.Nil(t, err, "could not read claims")

// 	return claims
// }

// func UnsafeClaims(t *testing.T, jws string, algs []jose.SignatureAlgorithm) map[string]any {
// 	parsedToken, err := jwt.ParseSigned(jws, algs)
// 	require.Nil(t, err, "invalid JWT")

// 	var claims map[string]any
// 	err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
// 	require.Nil(t, err, "could not read claims")

// 	return claims
// }
