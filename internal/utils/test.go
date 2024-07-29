package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/crud/inmemory"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	TestHost                          string = "https://example.com"
	TestKeyID                         string = "test_rsa256_key"
	TestClientID                      string = "test_client_id"
	TestClientSecret                  string = "test_client_secret"
	TestClientRedirectURI             string = "https://example.com/callback"
	TestClientRegistrationAccessToken string = "random_registration_access_token"
)

var (
	TestScope1           = goidc.NewScope("scope1")
	TestScope2           = goidc.NewScope("scope2")
	TestServerPrivateJWK = PrivateRS256JWK(nil, TestKeyID)
)

func NewTestClient(_ *testing.T) *goidc.Client {
	hashedRegistrationAccessToken, _ := bcrypt.GenerateFromPassword([]byte(TestClientRegistrationAccessToken), bcrypt.DefaultCost)
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(TestClientSecret), bcrypt.DefaultCost)
	return &goidc.Client{
		ID:                            TestClientID,
		HashedSecret:                  string(hashedClientSecret),
		HashedRegistrationAccessToken: string(hashedRegistrationAccessToken),
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.ClientAuthnSecretPost,
			RedirectURIS: []string{TestClientRedirectURI},
			Scopes:       fmt.Sprintf("%s %s %s", TestScope1, TestScope2, goidc.ScopeOpenID),
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantImplicit,
				goidc.GrantRefreshToken,
				goidc.GrantClientCredentials,
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

func NewTestContext(t *testing.T) *Context {
	config := Configuration{
		Profile:             goidc.ProfileOpenID,
		Host:                TestHost,
		ClientManager:       inmemory.NewClientManager(),
		GrantSessionManager: inmemory.NewGrantSessionManager(),
		AuthnSessionManager: inmemory.NewAuthnSessionManager(),
		Scopes:              []goidc.Scope{goidc.ScopeOpenID, TestScope1, TestScope2},
		PrivateJWKS:         jose.JSONWebKeySet{Keys: []jose.JSONWebKey{TestServerPrivateJWK}},
		ClientAuthnMethods:  []goidc.ClientAuthnType{goidc.ClientAuthnNone, goidc.ClientAuthnSecretPost},
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
		DefaultTokenSignatureKeyID:    TestServerPrivateJWK.KeyID,
		DefaultUserInfoSignatureKeyID: TestServerPrivateJWK.KeyID,
		UserInfoSignatureKeyIDs:       []string{TestServerPrivateJWK.KeyID},
		TokenOptions: func(client *goidc.Client, scopes string) (goidc.TokenOptions, error) {
			return goidc.TokenOptions{
				TokenLifetimeSecs: 60,
				TokenFormat:       goidc.TokenFormatJWT,
			}, nil
		},
		AuthenticationSessionTimeoutSecs: 60,
	}
	ctx := Context{
		Configuration: config,
		Req:           httptest.NewRequest(http.MethodGet, "/auth", nil),
		Resp:          httptest.NewRecorder(),
	}

	require.Nil(t, ctx.SaveClient(NewTestClient(t)), "could not create the test client")

	return &ctx
}

func AuthnSessions(_ *testing.T, ctx *Context) []*goidc.AuthnSession {
	sessionManager, _ := ctx.AuthnSessionManager.(*inmemory.AuthnSessionManager)
	sessions := make([]*goidc.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GrantSessions(_ *testing.T, ctx *Context) []*goidc.GrantSession {
	manager, _ := ctx.GrantSessionManager.(*inmemory.GrantSessionManager)
	tokens := make([]*goidc.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		tokens = append(tokens, t)
	}

	return tokens
}

func Clients(_ *testing.T, ctx *Context) []*goidc.Client {
	manager, _ := ctx.ClientManager.(*inmemory.ClientManager)
	clients := make([]*goidc.Client, 0, len(manager.Clients))
	for _, c := range manager.Clients {
		clients = append(clients, c)
	}

	return clients
}

func RawJWKS(jwk jose.JSONWebKey) []byte {
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	return jwks
}

func PrivateRS256JWK(t *testing.T, keyID string) jose.JSONWebKey {
	return PrivateRS256JWKWithUsage(t, keyID, goidc.KeyUsageSignature)
}

func PrivateRS256JWKWithUsage(
	_ *testing.T,
	keyID string,
	usage goidc.KeyUsage,
) jose.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       string(usage),
	}
}

func PrivatePS256JWK(t *testing.T, keyID string) jose.JSONWebKey {
	return PrivatePS256JWKWithUsage(t, keyID, goidc.KeyUsageSignature)
}

func PrivatePS256JWKWithUsage(
	_ *testing.T,
	keyID string,
	usage goidc.KeyUsage,
) jose.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.PS256),
		Use:       string(usage),
	}
}

func SafeClaims(t *testing.T, jws string, privateJWK jose.JSONWebKey) map[string]any {
	parsedToken, err := jwt.ParseSigned(jws, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(privateJWK.Algorithm)})
	require.Nil(t, err, "invalid JWT")

	var claims map[string]any
	err = parsedToken.Claims(privateJWK.Public().Key, &claims)
	require.Nil(t, err, "could not read claims")

	return claims
}

func UnsafeClaims(t *testing.T, jws string, algorithms []jose.SignatureAlgorithm) map[string]any {
	parsedToken, err := jwt.ParseSigned(jws, algorithms)
	require.Nil(t, err, "invalid JWT")

	var claims map[string]any
	err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
	require.Nil(t, err, "could not read claims")

	return claims
}
