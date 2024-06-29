package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/pkg/goidc"
)

const (
	TestClientID           string = "random_client_id"
	TestClientSecret       string = "random_client_secret"
	TestOpaqueGrantModelID string = "opaque_grant_model_id"
	TestJWTGrantModelID    string = "jwt_grant_model_id"
	TestHost               string = "https://example.com"
	TestKeyID              string = "rsa256_key"
)

func GetTestClient() goidc.Client {
	return goidc.Client{
		ID: TestClientID,
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.NoneAuthn,
			RedirectURIS: []string{"https://example.com"},
			Scopes:       "scope1 scope2 " + goidc.OpenIDScope,
			GrantTypes: []goidc.GrantType{
				goidc.AuthorizationCodeGrant,
				goidc.ClientCredentialsGrant,
				goidc.ImplicitGrant,
				goidc.RefreshTokenGrant,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.CodeResponse,
				goidc.IDTokenResponse,
				goidc.TokenResponse,
				goidc.CodeAndIDTokenResponse,
				goidc.CodeAndTokenResponse,
				goidc.IDTokenAndTokenResponse,
				goidc.CodeAndIDTokenAndTokenResponse,
			},
		},
	}
}

func GetTestInMemoryContext() Context {
	privateJWK := GetTestPrivateRS256JWK(TestKeyID)
	return Context{
		Configuration: Configuration{
			Profile:                       goidc.OpenIDProfile,
			Host:                          TestHost,
			ClientManager:                 inmemory.NewInMemoryClientManager(),
			GrantSessionManager:           inmemory.NewInMemoryGrantSessionManager(),
			AuthnSessionManager:           inmemory.NewInMemoryAuthnSessionManager(),
			PrivateJWKS:                   goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{privateJWK}},
			DefaultTokenSignatureKeyID:    privateJWK.GetKeyID(),
			DefaultUserInfoSignatureKeyID: privateJWK.GetKeyID(),
			UserInfoSignatureKeyIDs:       []string{privateJWK.GetKeyID()},
			GetTokenOptions: func(client goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.TokenOptions{
					TokenLifetimeSecs: 60,
					TokenFormat:       goidc.JWTTokenFormat,
				}, nil
			},
			AuthenticationSessionTimeoutSecs: 60,
		},
		Request:  httptest.NewRequest(http.MethodGet, TestHost, nil),
		Response: httptest.NewRecorder(),
		Logger:   slog.Default(),
	}
}

func GetDummyTestContext() Context {
	return Context{
		Configuration: Configuration{
			Profile: goidc.OpenIDProfile,
			Host:    TestHost,
		},
		Request: &http.Request{},
		Logger:  slog.Default(),
	}
}

func GetAuthnSessionsFromTestContext(ctx Context) []goidc.AuthnSession {
	sessionManager, _ := ctx.AuthnSessionManager.(*inmemory.InMemoryAuthnSessionManager)
	sessions := make([]goidc.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GetGrantSessionsFromTestContext(ctx Context) []goidc.GrantSession {
	manager, _ := ctx.GrantSessionManager.(*inmemory.InMemoryGrantSessionManager)
	tokens := make([]goidc.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		tokens = append(tokens, t)
	}

	return tokens
}

func GetTestPrivateRS256JWK(keyID string) goidc.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJSONWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       string(goidc.KeySignatureUsage),
	})
}

func GetTestPrivatePS256JWK(keyID string) goidc.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJSONWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.PS256),
		Use:       string(goidc.KeySignatureUsage),
	})
}

// TODO: get unsafe claims from token.
