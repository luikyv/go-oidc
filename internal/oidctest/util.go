package oidctest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var (
	Scope1 = goidc.NewScope("scope1")
	Scope2 = goidc.NewScope("scope2")
)

func PointerOf[T any](v T) *T { return &v }

func NewClient(tb testing.TB) (client *goidc.Client, secret string) {
	tb.Helper()

	secret = "test_secret"
	client = &goidc.Client{
		ID:     "test_client",
		Secret: "test_secret",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodSecretPost,
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

func NewContext(tb testing.TB) oidc.Context {
	tb.Helper()

	keyID := "test_server_key"
	jwk := PrivatePS256JWK(tb, keyID, goidc.KeyUsageSignature)
	manager := storage.NewManager(100)

	config := &oidc.Configuration{
		Profile:      goidc.ProfileOpenID,
		Host:         "https://example.com",
		GrantManager: manager,
		Scopes:       []goidc.Scope{goidc.ScopeOpenID, Scope1, Scope2},
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
		OpaqueTokenFunc: func(context.Context, *goidc.Grant) string {
			return uuid.NewString()
		},
		RefreshTokenFunc: func(context.Context) string {
			return uuid.NewString()
		},
		TokenOptionsFunc: func(
			_ context.Context,
			_ *goidc.Grant,
			_ *goidc.Client,
		) goidc.TokenOptions {
			return goidc.TokenOptions{
				JWTSigAlg:    goidc.SignatureAlgorithm(jwk.Algorithm),
				LifetimeSecs: 60,
				Format:       goidc.TokenFormatJWT,
			}
		},
		VerifyClientSecretFunc: func(_ context.Context, stored, presented string) error {
			if subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) != 1 {
				return errors.New("invalid client secret")
			}
			return nil
		},
		DCRHandleClientFunc: func(context.Context, string, *goidc.ClientMeta) error {
			return nil
		},
		DCRRegistrationTokenFunc: func(context.Context) string {
			return strutil.Random(50)
		},
		ConsumeJTIFunc: func(context.Context, string) error {
			return nil
		},
		ClientCertFunc: func(context.Context) (*x509.Certificate, error) {
			return nil, errors.New("the client certificate function was not defined")
		},
		TokenIntrospectionIsClientAllowedFunc: func(context.Context, *goidc.Client, goidc.TokenInfo) bool {
			return false
		},
		TokenRevocationIsClientAllowedFunc: func(context.Context, *goidc.Client) bool {
			return false
		},
		HandleErrorFunc: func(context.Context, error) {},
		RARValidateDetailFunc: func(context.Context, goidc.AuthDetail) error {
			return nil
		},
		OpenIDFedRequiredTrustMarksFunc: func(context.Context, *goidc.Client) []goidc.TrustMark {
			return nil
		},
		OpenIDFedHandleClientFunc: func(context.Context, *goidc.Client) error {
			return nil
		},
		RefreshTokenShouldIssueFunc: func(context.Context, *goidc.Client, *goidc.Grant) bool {
			return true
		},
		HandleGrantFunc: func(context.Context, *goidc.Grant) error {
			return nil
		},
		HandleTokenFunc: func(context.Context, *goidc.Token, *goidc.Grant) error {
			return nil
		},
		IDTokenClaimsFunc: func(context.Context, *goidc.Grant) map[string]any {
			return nil
		},
		UserInfoClaimsFunc: func(context.Context, *goidc.Grant) map[string]any {
			return nil
		},
		TokenClaimsFunc: func(context.Context, *goidc.Token, *goidc.Grant) map[string]any {
			return nil
		},
		PairwiseSubjectFunc: func(_ context.Context, sub string, _ *goidc.Client) string {
			return sub
		},
		PARHandleSessionFunc: func(context.Context, *goidc.AuthnSession, *goidc.Client) error {
			return nil
		},
		CIBAHandleSessionFunc: func(context.Context, *goidc.AuthnSession, *goidc.Client) error {
			return errors.New("ciba init back auth function is not set")
		},
		SSFScheduleVerificationEventFunc: func(context.Context, string, goidc.SSFStreamVerificationOptions) error {
			return errors.New("schedule verification event function is not set")
		},
		SSFHandleExpiredEventStreamFunc: func(context.Context, *goidc.SSFEventStream) error {
			return nil
		},
		VCHandlePreAuthCodeFunc: func(context.Context, string, goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
			return goidc.VCPreAuthCodeResult{}, errors.New("vc pre-authorized code handler is not set")
		},
		VCOfferIDFunc: func(context.Context) string {
			return uuid.NewString()
		},
		VCIssuerStateFunc: func(context.Context) string {
			return uuid.NewString()
		},
		AuthTimeoutSecs: 60,
		AuthnMethods: []goidc.AuthnMethod{
			goidc.AuthnMethodNone,
			goidc.AuthnMethodSecretPost,
			goidc.AuthnMethodSecretBasic,
			goidc.AuthnMethodPrivateKeyJWT,
			goidc.AuthnMethodSecretJWT,
			goidc.AuthnMethodSelfSignedTLS,
			goidc.AuthnMethodTLS,
		},
		UserInfoDefaultSigAlg:      goidc.SignatureAlgorithm(jwk.Algorithm),
		UserInfoSigAlgs:            []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(jwk.Algorithm)},
		IDTokenDefaultSigAlg:       goidc.SignatureAlgorithm(jwk.Algorithm),
		IDTokenSigAlgs:             []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(jwk.Algorithm)},
		WellKnownEndpoint:          "/.well-known/openid-configuration",
		JWKSEndpoint:               "/jwks",
		TokenEndpoint:              "/token",
		AuthorizationEndpoint:      "/authorize",
		PAREndpoint:                "/par",
		DCREndpoint:                "/register",
		UserInfoEndpoint:           "/userinfo",
		TokenIntrospectionEndpoint: "/introspect",
		JWTLifetimeSecs:            600,
		GrantIDFunc: func(context.Context) string {
			return uuid.NewString()
		},
		PARIDFunc: func(context.Context) string {
			return uuid.NewString()
		},
		CIBAIDFunc: func(context.Context) string {
			return uuid.NewString()
		},
		JWTIDFunc: func(context.Context) string {
			return uuid.NewString()
		},
		DeviceCodeFunc: func(context.Context) string {
			return uuid.NewString()
		},
		IDTokenLifetimeSecs:      60,
		SubIdentifierTypeDefault: goidc.SubIdentifierPublic,
		SubIdentifierTypes: []goidc.SubIdentifierType{
			goidc.SubIdentifierPublic,
		},
		HTTPClientFunc: func(_ context.Context) *http.Client {
			return &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				},
			}
		},
	}

	ctx := oidc.NewHTTPContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/auth", nil),
		config,
	)

	return ctx
}

func PrivateJWKS(tb testing.TB, ctx oidc.Context) goidc.JSONWebKeySet {
	tb.Helper()

	jwks, err := ctx.JWKS()
	if err != nil {
		tb.Fatal(err)
	}
	return jwks
}

func Manager(tb testing.TB, ctx oidc.Context) *storage.Manager {
	tb.Helper()
	m, _ := ctx.GrantManager.(*storage.Manager)
	return m
}

func AuthnSessions(tb testing.TB, ctx oidc.Context) []*goidc.AuthnSession {
	tb.Helper()

	m := Manager(tb, ctx)
	sessions := make([]*goidc.AuthnSession, 0, len(m.Sessions))
	for _, s := range m.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func Grants(t *testing.T, ctx oidc.Context) []*goidc.Grant {
	t.Helper()

	m := Manager(t, ctx)
	grants := make([]*goidc.Grant, 0, len(m.Grants))
	for _, g := range m.Grants {
		grants = append(grants, g)
	}

	return grants
}

func Tokens(t *testing.T, ctx oidc.Context) []*goidc.Token {
	t.Helper()

	m := Manager(t, ctx)
	tokens := make([]*goidc.Token, 0, len(m.Tokens))
	for _, tkn := range m.Tokens {
		tokens = append(tokens, tkn)
	}

	return tokens
}

func Clients(t *testing.T, ctx oidc.Context) []*goidc.Client {
	t.Helper()

	m := Manager(t, ctx)
	clients := make([]*goidc.Client, 0, len(m.Clients))
	for _, c := range m.Clients {
		clients = append(clients, c)
	}

	return clients
}

func PrivateRSAOAEPJWK(t *testing.T, keyID string) goidc.JSONWebKey {
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

func PrivateRSAOAEP256JWK(t *testing.T, keyID string) goidc.JSONWebKey {
	t.Helper()
	return privateRSAJWK(t, keyID, string(goidc.RSA_OAEP_256), goidc.KeyUsageEncryption)
}

func PrivateRS256JWK(t *testing.T, keyID string, usage goidc.KeyUsage) goidc.JSONWebKey {
	t.Helper()
	return privateRSAJWK(t, keyID, string(goidc.RS256), usage)
}

func PrivatePS256JWK(tb testing.TB, keyID string, usage goidc.KeyUsage) goidc.JSONWebKey {
	tb.Helper()
	return privateRSAJWK(tb, keyID, string(goidc.PS256), usage)
}

func privateRSAJWK(tb testing.TB, keyID string, alg string, usage goidc.KeyUsage) goidc.JSONWebKey {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("could not generated PS256 JWK: %v", err)
	}
	return goidc.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: alg,
		Use:       string(usage),
	}
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

func Sign(tb testing.TB, claims map[string]any, jwk goidc.JSONWebKey) string {
	tb.Helper()
	return SignWithOptions(tb, claims, jwk, nil)
}

// DPoPProofOptions configures DPoP proof generation.
type DPoPProofOptions struct {
	Method string
	URI    string
	// Key is the private key used to sign the proof. If nil, a fresh ES256 key
	// is generated.
	Key crypto.PrivateKey
}

// DPoPProof generates a DPoP proof JWT.
// It returns the serialized JWT and the JWK thumbprint of the signing key.
func DPoPProof(tb testing.TB, opts DPoPProofOptions) (dpopJWT string, thumbprint string) {
	tb.Helper()

	key := opts.Key
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			tb.Fatalf("could not generate EC key: %v", err)
		}
		key = k
	}

	var pubKey crypto.PublicKey
	var alg jose.SignatureAlgorithm
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		pubKey = k.Public()
		alg = jose.ES256
	case *rsa.PrivateKey:
		pubKey = k.Public()
		alg = jose.PS256
	default:
		tb.Fatalf("unsupported DPoP key type: %T", key)
	}

	jwk := jose.JSONWebKey{Key: pubKey, Algorithm: string(alg)}
	jkt, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		tb.Fatalf("could not compute JWK thumbprint: %v", err)
	}
	thumbprint = base64.RawURLEncoding.EncodeToString(jkt)

	signerOpts := (&jose.SignerOptions{}).
		WithType("dpop+jwt").
		WithHeader("jwk", jwk)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, signerOpts)
	if err != nil {
		tb.Fatalf("could not create DPoP signer: %v", err)
	}

	claims := map[string]any{
		"jti": uuid.NewString(),
		"htm": opts.Method,
		"htu": opts.URI,
		"iat": time.Now().Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		tb.Fatalf("could not marshal DPoP claims: %v", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		tb.Fatalf("could not sign DPoP proof: %v", err)
	}

	dpopJWT, err = jws.CompactSerialize()
	if err != nil {
		tb.Fatalf("could not serialize DPoP proof: %v", err)
	}

	return dpopJWT, thumbprint
}

func SignWithOptions(tb testing.TB, claims map[string]any, jwk goidc.JSONWebKey, opts *jose.SignerOptions) string {
	tb.Helper()
	jws, _ := joseutil.Sign(claims, jose.SigningKey{Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm), Key: jwk}, opts)
	return jws
}
