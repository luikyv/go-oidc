package oidctest

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
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

var (
	Scope1 = goidc.NewScope("scope1")
	Scope2 = goidc.NewScope("scope2")
)

func NewClient(t *testing.T) (client *goidc.Client, secret string) {
	t.Helper()

	secret = "test_secret"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	client = &goidc.Client{
		ID:           "test_client",
		HashedSecret: string(hashedSecret),
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.ClientAuthnSecretPost,
			RedirectURIs: []string{"https://example.com/callback"},
			ScopeIDs:     fmt.Sprintf("%s %s %s", Scope1.ID, Scope2.ID, goidc.ScopeOpenID.ID),
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

	return client, secret
}

func NewContext(t *testing.T) *oidc.Context {
	t.Helper()

	keyID := "test_server_key"
	jwk := PrivatePS256JWK(t, keyID, goidc.KeyUsageSignature)

	config := oidc.Configuration{
		Host: "https://example.com",

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
			goidc.ClientAuthnSelfSignedTLS,
			goidc.ClientAuthnTLS,
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
		IDTokenLifetimeSecs:         60,
		SubIdentifierTypes: []goidc.SubjectIdentifierType{
			goidc.SubjectIdentifierPublic,
		},
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

func SafeClaims(jws string, jwk jose.JSONWebKey) (map[string]any, error) {
	parsedToken, err := jwt.ParseSigned(jws, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jwk.Algorithm)})
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	err = parsedToken.Claims(jwk.Public().Key, &claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
