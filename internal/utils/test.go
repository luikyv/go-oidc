package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/require"
)

const (
	TestHost              string = "https://example.com"
	TestKeyID             string = "test_rsa256_key"
	TestClientID          string = "test_client_id"
	TestClientRedirectURI string = "https://example.com/callback"
)

var (
	TestScope1           = goidc.NewScope("scope1")
	TestScope2           = goidc.NewScope("scope2")
	TestServerPrivateJWK = PrivateRS256JWK(nil, TestKeyID)
)

func NewTestClient(_ *testing.T) goidc.Client {
	return goidc.Client{
		ID: TestClientID,
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.ClientAuthnNone,
			RedirectURIS: []string{TestClientRedirectURI},
			Scopes:       fmt.Sprintf("%s %s %s", TestScope1, TestScope2, goidc.ScopeOpenID),
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantClientCredentials,
				goidc.GrantImplicit,
				goidc.GrantRefreshToken,
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
		},
	}
}

func NewTestContext(t *testing.T) OAuthContext {
	config := Configuration{
		Profile:                       goidc.ProfileOpenID,
		Host:                          TestHost,
		ClientManager:                 inmemory.NewClientManager(),
		GrantSessionManager:           inmemory.NewGrantSessionManager(),
		AuthnSessionManager:           inmemory.NewAuthnSessionManager(),
		OAuthScopes:                   []goidc.Scope{goidc.ScopeOpenID, TestScope1, TestScope2},
		PrivateJWKS:                   goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{TestServerPrivateJWK}},
		DefaultTokenSignatureKeyID:    TestServerPrivateJWK.KeyID(),
		DefaultUserInfoSignatureKeyID: TestServerPrivateJWK.KeyID(),
		UserInfoSignatureKeyIDs:       []string{TestServerPrivateJWK.KeyID()},
		TokenOptions: func(client goidc.Client, scopes string) (goidc.TokenOptions, error) {
			return goidc.TokenOptions{
				TokenLifetimeSecs: 60,
				TokenFormat:       goidc.TokenFormatJWT,
			}, nil
		},
		AuthenticationSessionTimeoutSecs: 60,
	}
	ctx := OAuthContext{
		Configuration: config,
		Request:       httptest.NewRequest(http.MethodGet, TestHost, nil),
		Response:      httptest.NewRecorder(),
	}

	require.Nil(t, ctx.CreateOrUpdateClient(NewTestClient(t)), "could not create the test client")

	return ctx
}

func AuthnSessions(_ *testing.T, ctx OAuthContext) []goidc.AuthnSession {
	sessionManager, _ := ctx.AuthnSessionManager.(*inmemory.AuthnSessionManager)
	sessions := make([]goidc.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GrantSessions(_ *testing.T, ctx OAuthContext) []goidc.GrantSession {
	manager, _ := ctx.GrantSessionManager.(*inmemory.GrantSessionManager)
	tokens := make([]goidc.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		tokens = append(tokens, t)
	}

	return tokens
}

func PrivateRS256JWK(t *testing.T, keyID string) goidc.JSONWebKey {
	return PrivateRS256JWKWithUsage(t, keyID, goidc.KeyUsageSignature)
}

func PrivateRS256JWKWithUsage(
	_ *testing.T,
	keyID string,
	usage goidc.KeyUsage,
) goidc.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJSONWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       string(usage),
	})
}

func PrivatePS256JWK(t *testing.T, keyID string) goidc.JSONWebKey {
	return PrivatePS256JWKWithUsage(t, keyID, goidc.KeyUsageSignature)
}

func PrivatePS256JWKWithUsage(
	_ *testing.T,
	keyID string,
	usage goidc.KeyUsage,
) goidc.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJSONWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.PS256),
		Use:       string(usage),
	})
}

func UnsafeClaims(t *testing.T, jws string, algorithms []jose.SignatureAlgorithm) map[string]any {
	parsedToken, err := jwt.ParseSigned(jws, algorithms)
	require.Nil(t, err, "invalid JWT")

	var claims map[string]any
	err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
	require.Nil(t, err, "could not read claims")

	return claims
}
