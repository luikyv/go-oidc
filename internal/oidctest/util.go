package oidctest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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

func NewClient(t testing.TB) (client *goidc.Client, secret string) {
	t.Helper()

	secret = "test_secret"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	client = &goidc.Client{
		ID:           "test_client",
		HashedSecret: string(hashedSecret),
		ClientMetaInfo: goidc.ClientMetaInfo{
			TokenAuthnMethod: goidc.ClientAuthnSecretPost,
			RedirectURIs:     []string{"https://example.com/callback"},
			ScopeIDs:         fmt.Sprintf("%s %s %s", Scope1.ID, Scope2.ID, goidc.ScopeOpenID.ID),
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

func NewContext(t testing.TB) oidc.Context {
	t.Helper()

	keyID := "test_server_key"
	jwk := PrivatePS256JWK(t, keyID, goidc.KeyUsageSignature)

	config := &oidc.Configuration{
		Profile: goidc.ProfileOpenID,
		Host:    "https://example.com",

		ClientManager:       storage.NewClientManager(),
		AuthnSessionManager: storage.NewAuthnSessionManager(),
		GrantSessionManager: storage.NewGrantSessionManager(),

		Scopes: []goidc.Scope{goidc.ScopeOpenID, Scope1, Scope2},
		JWKSFunc: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}}, nil
		},
		GrantTypes: []goidc.GrantType{
			goidc.GrantAuthorizationCode,
			goidc.GrantClientCredentials,
			goidc.GrantImplicit,
			goidc.GrantRefreshToken,
			goidc.GrantJWTBearer,
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
		TokenOptionsFunc: func(
			grantInfo goidc.GrantInfo,
			client *goidc.Client,
		) goidc.TokenOptions {
			return goidc.TokenOptions{
				JWTSigAlg:    goidc.SignatureAlgorithm(jwk.Algorithm),
				LifetimeSecs: 60,
				Format:       goidc.TokenFormatJWT,
			}
		},
		AuthnSessionTimeoutSecs: 60,
		TokenAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnNone,
			goidc.ClientAuthnSecretPost,
			goidc.ClientAuthnSecretBasic,
			goidc.ClientAuthnPrivateKeyJWT,
			goidc.ClientAuthnSecretJWT,
			goidc.ClientAuthnSelfSignedTLS,
			goidc.ClientAuthnTLS,
		},
		UserInfoDefaultSigAlg:       goidc.SignatureAlgorithm(jwk.Algorithm),
		UserInfoSigAlgs:             []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(jwk.Algorithm)},
		IDTokenDefaultSigAlg:        goidc.SignatureAlgorithm(jwk.Algorithm),
		IDTokenSigAlgs:              []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(jwk.Algorithm)},
		EndpointWellKnown:           "/.well-known/openid-configuration",
		EndpointJWKS:                "/jwks",
		EndpointToken:               "/token",
		EndpointAuthorize:           "/authorize",
		EndpointPushedAuthorization: "/par",
		EndpointDCR:                 "/register",
		EndpointUserInfo:            "/userinfo",
		EndpointIntrospection:       "/introspect",
		JWTLifetimeSecs:             600,
		IDTokenLifetimeSecs:         60,
		DefaultSubIdentifierType:    goidc.SubIdentifierPublic,
		SubIdentifierTypes: []goidc.SubIdentifierType{
			goidc.SubIdentifierPublic,
		},
		HTTPClientFunc: func(_ context.Context) *http.Client {
			return &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		},
	}

	ctx := oidc.NewContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/auth", nil),
		config,
	)

	return ctx
}

func PrivateJWKS(t testing.TB, ctx oidc.Context) goidc.JSONWebKeySet {
	t.Helper()

	jwks, err := ctx.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	return jwks
}

func AuthnSessions(t testing.TB, ctx oidc.Context) []*goidc.AuthnSession {
	t.Helper()

	sessionManager, _ := ctx.AuthnSessionManager.(*storage.AuthnSessionManager)
	sessions := make([]*goidc.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GrantSessions(t *testing.T, ctx oidc.Context) []*goidc.GrantSession {
	t.Helper()

	manager, _ := ctx.GrantSessionManager.(*storage.GrantSessionManager)
	tokens := make([]*goidc.GrantSession, 0, len(manager.Sessions))
	for _, t := range manager.Sessions {
		tokens = append(tokens, t)
	}

	return tokens
}

func Clients(t *testing.T, ctx oidc.Context) []*goidc.Client {
	t.Helper()

	manager, _ := ctx.ClientManager.(*storage.ClientManager)
	clients := make([]*goidc.Client, 0, len(manager.Clients))
	for _, c := range manager.Clients {
		clients = append(clients, c)
	}

	return clients
}

func PrivateRSAOAEPJWK(
	t *testing.T,
	keyID string,
) goidc.JSONWebKey {
	t.Helper()

	jwkStr := `
		{
		"p": "6Kn6z5npGNQ_N6z7Ujp4p3SkaRrgTRLNq1k-NqKeyYPUsqOrwddoeuZ_xZzoKhBDehSepsrk8fnJ0D2Y1mInufgoXpPI0raDO5HTeymUj8b6fvZEHOBukv4XHtu01Gp7aetXX-6Cd8Hw0hSpdGSdDldh3S92eULxyUaOQd5XRc0",
		"kty": "RSA",
		"q": "xjk0Hy_Bh93zw2u5u-t446NZZWfP9jPAiBeVPHXhzpmsq8-K_t9xnIVM0KScxEZ7VzqXcVpLYBBJVxBeCS_qs4P0AHwBsqECOExSD4oIq7qJUG4xjFQ9g78pbCCnXB18uQr0MoWu85XJaOVudyDLgXgYs-kbJvNQ9-KknBRWp1M",
		"d": "eeqF_6aoCO79D3Yf1dDDOVaakrmaPfFsiUNqj-yiwcPXG7PEIRlvkN7zXqkGSOPXYQ99X9TXHa0OsHWIDYth1sxmtpY0NZkEwUKkOq4QgKbjMZOzUimwlyo9NmzOM1lwj1PXjSeaH9921_jQLYj7bZ6PVJeir8BhCz720MSsOc0PjYYm78Fm57lilsJYxLqr3tu16TZ4n77ZFu4yDSkm91J0iBUTUtMsAQdeFfkaPqdUWftaQqzTmTvTlExQQE3rtSKClSeJUZBvB5T6MGOizZ8d0qVgP7k4AakhaOjRX97jEH-FNKmRrvSyrh66QK0BTZRyd3zI6H0z9NMT2KzeqQ",
		"e": "AQAB",
		"use": "enc",
		"qi": "mYkPTGpY1YJo-b-f8RbX0lO6PYSPfjgm3UB58FQwUS7uiEgUmWs2DmGC9LCUfUc6V1qcnq9C_IT76-4nXKI7DucAdizBHZZf4lSr7HJ75gCUdeIXkBZSCTJLB9OUWBaZ-LhWLjVECf2UmMbSFOLYHshIOgNWpVqWFQLY4xDXpvY",
		"dp": "hqfqO0DOwcoFlImPIzYoInLFvPcLHlBlrGgIM8LGt8aO0Z0ciSHMnGTPSmXXkJC9HOjWMZ54BvwUq2sbC-jfKSjQ5HwP3LQ5G774cO3Nx7DXxaduIHBcTsK0Su3JqK7AIrtMZH88D2e1o0DGGlEo_OXiBAu2O9Rc76rgJosyY3k",
		"alg": "RSA-OAEP",
		"dq": "ZD9Z1MvaHFRri1FXxWn44WcjNt2hlunlXO5QUxtq74lYgiucJ_npAzeG-Z3Gipz6k8rV_EWmCRczgAyPAiZxlAgPxo7wbN5wuPggKCuu5uqXt02DUWzpD1AGKuD4wuVGxm57wXFKYXZHPf2KOEUlpnyOQa6KRNCZCkRc63J9wHE",
		"n": "tCd1NEgyMS87vQncSxB2XS8ywCHgYKt4RyibIMxlMBdTEG1BBzICAq5mlITzBJni_pRM25ugxjdVdCR1szc91oLi2cPQESlwsOaj2wCW_d3W8JCQA5Wln_TZtKmFCviDVQIxVZz7CeiL0irRjbrd7jjEx10VREvZt49LK0JbP6nQ44E-_zAN8LUQQgwCgB_IF0dvSYGVJJ-yAUxknwpaTGUUMFjhR7Nk49ya812Z1tIjEVgGOo1LOQoUItEn1Gr73cy5zDemzy6Y0LcFeiDj5GQfqIsI2cIM3Mk9Medc-YsYQ0UfdmKZkyLwytnR2tH6aGp0_zCyVooIDHcXe7Jcdw"
	}`
	var jwk goidc.JSONWebKey
	if err := json.Unmarshal([]byte(jwkStr), &jwk); err != nil {
		t.Fatal(err)
	}
	jwk.KeyID = keyID
	return jwk
}

func PrivateRSAOAEP256JWK(
	t *testing.T,
	keyID string,
) goidc.JSONWebKey {
	return privateRSAJWK(t, keyID, string(goidc.RSA_OAEP_256), goidc.KeyUsageEncryption)
}

func PrivateRS256JWK(
	t *testing.T,
	keyID string,
	usage goidc.KeyUsage,
) goidc.JSONWebKey {
	return privateRSAJWK(t, keyID, string(goidc.RS256), usage)
}

func PrivatePS256JWK(
	t testing.TB,
	keyID string,
	usage goidc.KeyUsage,
) goidc.JSONWebKey {
	return privateRSAJWK(t, keyID, string(goidc.PS256), usage)
}

func privateRSAJWK(
	t testing.TB,
	keyID string,
	alg string,
	usage goidc.KeyUsage,
) goidc.JSONWebKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generated PS256 JWK: %v", err)
	}
	return goidc.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: string(alg),
		Use:       string(usage),
	}
}

func RawJWKS(jwk goidc.JSONWebKey) []byte {
	jwks, _ := json.Marshal(goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jwk}})
	return jwks
}

func SafeClaims(jws string, jwk goidc.JSONWebKey) (map[string]any, error) {
	parsedToken, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(jwk.Algorithm)})
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

func UnsafeClaims(jws string, algs ...goidc.SignatureAlgorithm) (map[string]any, error) {
	parsedToken, err := jwt.ParseSigned(jws, algs)
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func Sign(t testing.TB, claims map[string]any, jwk goidc.JSONWebKey) string {
	t.Helper()

	opts := &jose.SignerOptions{}
	opts = opts.WithHeader("kid", jwk.KeyID).WithHeader("alg", jwk.Algorithm).WithType("JWT")

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm), Key: jwk}, opts)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	return jws
}
