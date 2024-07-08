package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
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

var (
	Scope1 = goidc.NewScope("scope1")
	Scope2 = goidc.NewScope("scope2")
)

func GetTestClient() goidc.Client {
	return goidc.Client{
		ID: TestClientID,
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.ClientAuthnNone,
			RedirectURIS: []string{"https://example.com"},
			Scopes:       fmt.Sprintf("%s %s %s", Scope1, Scope2, goidc.ScopeOpenID),
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

func GetTestInMemoryContext() OAuthContext {
	privateJWK := GetTestPrivateRS256JWK(TestKeyID)
	return OAuthContext{
		Configuration: Configuration{
			Profile:                       goidc.ProfileOpenID,
			Host:                          TestHost,
			ClientManager:                 inmemory.NewClientManager(),
			GrantSessionManager:           inmemory.NewGrantSessionManager(),
			AuthnSessionManager:           inmemory.NewAuthnSessionManager(),
			Scopes:                        []goidc.Scope{goidc.ScopeOpenID, Scope1, Scope2},
			PrivateJWKS:                   goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{privateJWK}},
			DefaultTokenSignatureKeyID:    privateJWK.GetKeyID(),
			DefaultUserInfoSignatureKeyID: privateJWK.GetKeyID(),
			UserInfoSignatureKeyIDs:       []string{privateJWK.GetKeyID()},
			GetTokenOptions: func(client goidc.Client, scopes string) (goidc.TokenOptions, error) {
				return goidc.TokenOptions{
					TokenLifetimeSecs: 60,
					TokenFormat:       goidc.TokenFormatJWT,
				}, nil
			},
			AuthenticationSessionTimeoutSecs: 60,
		},
		Request:  httptest.NewRequest(http.MethodGet, TestHost, nil),
		Response: httptest.NewRecorder(),
		Logger:   slog.Default(),
	}
}

func GetDummyTestContext() OAuthContext {
	return OAuthContext{
		Configuration: Configuration{
			Profile: goidc.ProfileOpenID,
			Host:    TestHost,
			Scopes:  []goidc.Scope{goidc.ScopeOpenID, Scope1, Scope2},
		},
		Request: &http.Request{},
		Logger:  slog.Default(),
	}
}

func GetAuthnSessionsFromTestContext(ctx OAuthContext) []goidc.AuthnSession {
	sessionManager, _ := ctx.AuthnSessionManager.(*inmemory.AuthnSessionManager)
	sessions := make([]goidc.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GetGrantSessionsFromTestContext(ctx OAuthContext) []goidc.GrantSession {
	manager, _ := ctx.GrantSessionManager.(*inmemory.GrantSessionManager)
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
		Use:       string(goidc.KeyUsageSignature),
	})
}

func GetTestPrivatePS256JWK(keyID string) goidc.JSONWebKey {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return goidc.NewJSONWebKey(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(jose.PS256),
		Use:       string(goidc.KeyUsageSignature),
	})
}

// TODO: get unsafe claims from token.
