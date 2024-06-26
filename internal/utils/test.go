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
	TestClientId           string = "random_client_id"
	TestClientSecret       string = "random_client_secret"
	TestOpaqueGrantModelId string = "opaque_grant_model_id"
	TestJwtGrantModelId    string = "jwt_grant_model_id"
	TestHost               string = "https://example.com"
	TestKeyId              string = "rsa256_key"
)

func GetTestClient() goidc.Client {
	return goidc.Client{
		Id: TestClientId,
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.NoneAuthn,
			RedirectUris: []string{"https://example.com"},
			Scopes:       "scope1 scope2 " + goidc.OpenIdScope,
			GrantTypes: []goidc.GrantType{
				goidc.AuthorizationCodeGrant,
				goidc.ClientCredentialsGrant,
				goidc.ImplicitGrant,
				goidc.RefreshTokenGrant,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.CodeResponse,
				goidc.IdTokenResponse,
				goidc.TokenResponse,
				goidc.CodeAndIdTokenResponse,
				goidc.CodeAndTokenResponse,
				goidc.IdTokenAndTokenResponse,
				goidc.CodeAndIdTokenAndTokenResponse,
			},
		},
	}
}

func GetTestInMemoryContext() Context {
	privateJwk := GetTestPrivateRs256Jwk(TestKeyId)
	return Context{
		Configuration: Configuration{
			Profile:                       goidc.OpenIdProfile,
			Host:                          TestHost,
			ClientManager:                 inmemory.NewInMemoryClientManager(),
			GrantSessionManager:           inmemory.NewInMemoryGrantSessionManager(),
			AuthnSessionManager:           inmemory.NewInMemoryAuthnSessionManager(),
			PrivateJwks:                   goidc.JsonWebKeySet{Keys: []goidc.JsonWebKey{privateJwk}},
			DefaultTokenSignatureKeyId:    privateJwk.GetKeyId(),
			DefaultUserInfoSignatureKeyId: privateJwk.GetKeyId(),
			UserInfoSignatureKeyIds:       []string{privateJwk.GetKeyId()},
			GetTokenOptions: func(client goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.TokenOptions{
					TokenExpiresInSecs: 60,
					TokenFormat:        goidc.JwtTokenFormat,
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
			Profile: goidc.OpenIdProfile,
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

func GetTestPrivateRs256Jwk(keyId string) goidc.JsonWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJsonWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Algorithm: string(jose.RS256),
		Use:       string(goidc.KeySignatureUsage),
	})
}

func GetTestPrivatePs256Jwk(keyId string) goidc.JsonWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJsonWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Algorithm: string(jose.PS256),
		Use:       string(goidc.KeySignatureUsage),
	})
}

// TODO: get unsafe claims from token.
