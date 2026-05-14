package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestTokenAuthnSigAlgs(t *testing.T) {
	tests := []struct {
		name string
		ctx  oidc.Context
		want []goidc.SignatureAlgorithm
	}{
		{
			name: "no methods",
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{},
			},
			want: nil,
		},
		{
			name: "private key jwt",
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods:              []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT},
					TokenAuthnPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
				},
			},
			want: []goidc.SignatureAlgorithm{goidc.PS256},
		},
		{
			name: "secret jwt",
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods:          []goidc.AuthnMethod{goidc.AuthnMethodSecretJWT},
					TokenAuthnSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
				},
			},
			want: []goidc.SignatureAlgorithm{goidc.HS256},
		},
		{
			name: "both methods",
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods:              []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT, goidc.AuthnMethodSecretJWT},
					TokenAuthnPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
					TokenAuthnSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.HS256},
				},
			},
			want: []goidc.SignatureAlgorithm{goidc.PS256, goidc.HS256},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.ctx.TokenAuthnSigAlgs()
			if diff := cmp.Diff(test.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestHandleDynamicClient(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*oidc.Context)
		validate  func(*testing.T, error, *goidc.ClientMeta)
	}{
		{
			name:      "default no-op",
			configure: func(*oidc.Context) {},
			validate: func(t *testing.T, err error, clientMeta *goidc.ClientMeta) {
				t.Helper()
				if err != nil {
					t.Fatalf("HandleDynamicClient() error = %v", err)
				}
				if clientMeta.TokenAuthnMethod != "" {
					t.Fatalf("TokenAuthnMethod = %q, want empty", clientMeta.TokenAuthnMethod)
				}
			},
		},
		{
			name: "custom handler",
			configure: func(ctx *oidc.Context) {
				ctx.DCRHandleClientFunc = func(_ context.Context, _ string, meta *goidc.ClientMeta) error {
					meta.TokenAuthnMethod = goidc.AuthnMethodNone
					return nil
				}
			},
			validate: func(t *testing.T, err error, clientMeta *goidc.ClientMeta) {
				t.Helper()
				if err != nil {
					t.Fatalf("HandleDynamicClient() error = %v", err)
				}
				if clientMeta.TokenAuthnMethod != goidc.AuthnMethodNone {
					t.Fatalf("TokenAuthnMethod = %q, want %q", clientMeta.TokenAuthnMethod, goidc.AuthnMethodNone)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newContext()
			test.configure(&ctx)

			clientMeta := &goidc.ClientMeta{}
			err := ctx.HandleDynamicClient("random_id", clientMeta)

			test.validate(t, err, clientMeta)
		})
	}
}

func TestPolicy(t *testing.T) {
	ctx := newContext()
	ctx.Policies = []goidc.AuthnPolicy{
		goidc.NewPolicy("policy_1", nil, nil),
	}

	policy := ctx.Policy("policy_1")
	if policy.ID != "policy_1" {
		t.Fatalf("Policy().ID = %q, want %q", policy.ID, "policy_1")
	}
}

func TestAvailablePolicy(t *testing.T) {
	tests := []struct {
		name     string
		policies []goidc.AuthnPolicy
		validate func(*testing.T, goidc.AuthnPolicy, bool)
	}{
		{
			name: "returns first available policy",
			policies: []goidc.AuthnPolicy{
				goidc.NewPolicy("unavailable", func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
					return false
				}, nil),
				goidc.NewPolicy("available", func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
					return true
				}, nil),
			},
			validate: func(t *testing.T, policy goidc.AuthnPolicy, ok bool) {
				t.Helper()
				if !ok {
					t.Fatal("AvailablePolicy() did not find the available policy")
				}
				if policy.ID != "available" {
					t.Fatalf("AvailablePolicy().ID = %q, want %q", policy.ID, "available")
				}
			},
		},
		{
			name: "returns false when none available",
			policies: []goidc.AuthnPolicy{
				goidc.NewPolicy("unavailable", func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
					return false
				}, nil),
			},
			validate: func(t *testing.T, policy goidc.AuthnPolicy, ok bool) {
				t.Helper()
				if ok {
					t.Fatalf("AvailablePolicy() found unexpected policy %q", policy.ID)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newContext()
			ctx.Policies = test.policies

			policy, ok := ctx.AvailablePolicy(&goidc.AuthnSession{}, &goidc.Client{})
			test.validate(t, policy, ok)
		})
	}
}

func TestBaseURL(t *testing.T) {
	ctx := newContext()
	ctx.Host = "https://example.com"
	ctx.EndpointPrefix = "/auth"

	if got := ctx.BaseURL(); got != "https://example.com/auth" {
		t.Fatalf("BaseURL() = %q, want %q", got, "https://example.com/auth")
	}
}

func TestMTLSBaseURL(t *testing.T) {
	ctx := newContext()
	ctx.MTLSHost = "https://mtls-example.com"
	ctx.EndpointPrefix = "/auth"

	if got := ctx.MTLSBaseURL(); got != "https://mtls-example.com/auth" {
		t.Fatalf("MTLSBaseURL() = %q, want %q", got, "https://mtls-example.com/auth")
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		validate func(*testing.T, string, bool)
	}{
		{
			name:   "present",
			header: "Bearer access_token",
			validate: func(t *testing.T, token string, ok bool) {
				t.Helper()
				if !ok {
					t.Fatal("BearerToken() did not find the token")
				}
				if token != "access_token" {
					t.Fatalf("BearerToken() = %q, want %q", token, "access_token")
				}
			},
		},
		{
			name:   "missing",
			header: "",
			validate: func(t *testing.T, token string, ok bool) {
				t.Helper()
				if ok {
					t.Fatalf("BearerToken() found unexpected token %q", token)
				}
			},
		},
		{
			name:   "not bearer",
			header: "DPoP token",
			validate: func(t *testing.T, token string, ok bool) {
				t.Helper()
				if ok {
					t.Fatalf("BearerToken() found unexpected token %q", token)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newContext()
			if test.header != "" {
				ctx.Request.Header.Set("Authorization", test.header)
			}

			token, ok := ctx.BearerToken()
			test.validate(t, token, ok)
		})
	}
}

func TestAuthorizationToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		validate func(*testing.T, string, goidc.TokenType, bool)
	}{
		{
			name:   "bearer token",
			header: "Bearer access_token",
			validate: func(t *testing.T, token string, tokenType goidc.TokenType, ok bool) {
				t.Helper()
				if !ok {
					t.Fatal("AuthorizationToken() did not find the token")
				}
				if token != "access_token" {
					t.Fatalf("AuthorizationToken() token = %q, want %q", token, "access_token")
				}
				if tokenType != goidc.TokenTypeBearer {
					t.Fatalf("AuthorizationToken() type = %q, want %q", tokenType, goidc.TokenTypeBearer)
				}
			},
		},
		{
			name:   "missing",
			header: "",
			validate: func(t *testing.T, token string, tokenType goidc.TokenType, ok bool) {
				t.Helper()
				if ok {
					t.Fatalf("AuthorizationToken() found unexpected token %q of type %q", token, tokenType)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newContext()
			if test.header != "" {
				ctx.Request.Header.Set("Authorization", test.header)
			}

			token, tokenType, ok := ctx.AuthorizationToken()
			test.validate(t, token, tokenType, ok)
		})
	}
}

func TestHeader(t *testing.T) {
	ctx := newContext()
	ctx.Request.Header.Set("Test-Header", "test_value")

	header, ok := ctx.Header("Test-Header")
	if !ok {
		t.Fatal("Header() did not find the header")
	}
	if header != "test_value" {
		t.Fatalf("Header() = %q, want %q", header, "test_value")
	}
}

func TestSigAlgs(t *testing.T) {
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)
	encryptionKey := oidctest.PrivatePS256JWK(t, "encryption_key", goidc.KeyUsageEncryption)
	ctx := newContext()
	ctx.JWKSFunc = func(context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey, encryptionKey}}, nil
	}

	algs, err := ctx.SigAlgs()
	if err != nil {
		t.Fatalf("SigAlgs() error = %v", err)
	}

	want := []goidc.SignatureAlgorithm{goidc.PS256}
	if diff := cmp.Diff(want, algs); diff != "" {
		t.Fatal(diff)
	}
}

func TestJWKSHelpers(t *testing.T) {
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)
	ctx := newContext()
	ctx.JWKSFunc = func(context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}, nil
	}

	t.Run("public jwks", func(t *testing.T) {
		publicJWKS, err := ctx.PublicJWKS()
		if err != nil {
			t.Fatalf("PublicJWKS() error = %v", err)
		}
		if len(publicJWKS.Keys) != 1 {
			t.Fatalf("len(PublicJWKS().Keys) = %d, want 1", len(publicJWKS.Keys))
		}
		if publicJWKS.Keys[0].KeyID != signingKey.KeyID {
			t.Fatalf("PublicJWKS().Keys[0].KeyID = %q, want %q", publicJWKS.Keys[0].KeyID, signingKey.KeyID)
		}
		if !publicJWKS.Keys[0].IsPublic() {
			t.Fatal("PublicJWKS() returned a non-public key")
		}
	})

	t.Run("public jwk", func(t *testing.T) {
		publicJWK, err := ctx.PublicJWK("signing_key")
		if err != nil {
			t.Fatalf("PublicJWK() error = %v", err)
		}
		if publicJWK.KeyID != signingKey.KeyID {
			t.Fatalf("PublicJWK().KeyID = %q, want %q", publicJWK.KeyID, signingKey.KeyID)
		}
		if !publicJWK.IsPublic() {
			t.Fatal("PublicJWK() returned a non-public key")
		}
	})

	t.Run("private jwk", func(t *testing.T) {
		privateJWK, err := ctx.JWK("signing_key")
		if err != nil {
			t.Fatalf("JWK() error = %v", err)
		}
		if privateJWK.KeyID != signingKey.KeyID {
			t.Fatalf("JWK().KeyID = %q, want %q", privateJWK.KeyID, signingKey.KeyID)
		}
		if privateJWK.IsPublic() {
			t.Fatal("JWK() returned a public key")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		_, err := ctx.JWK("missing")
		if err == nil {
			t.Fatal("JWK() error = nil, want non-nil")
		}
	})
}

func TestTokenAndPolicyHooks(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, oidc.Context)
	}{
		{
			name: "token introspection client allowed",
			run: func(t *testing.T, ctx oidc.Context) {
				client := &goidc.Client{}
				info := goidc.TokenInfo{}

				if ctx.TokenIntrospectionIsClientAllowed(client, info) {
					t.Fatal("TokenIntrospectionIsClientAllowed() = true, want false by default")
				}

				ctx.TokenIntrospectionIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
					return true
				}
				if !ctx.TokenIntrospectionIsClientAllowed(client, info) {
					t.Fatal("TokenIntrospectionIsClientAllowed() = false, want true")
				}
			},
		},
		{
			name: "token revocation client allowed",
			run: func(t *testing.T, ctx oidc.Context) {
				client := &goidc.Client{}

				if ctx.TokenRevocationIsClientAllowed(client) {
					t.Fatal("TokenRevocationIsClientAllowed() = true, want false by default")
				}

				ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
					return true
				}
				if !ctx.TokenRevocationIsClientAllowed(client) {
					t.Fatal("TokenRevocationIsClientAllowed() = false, want true")
				}
			},
		},
		{
			name: "client cert",
			run: func(t *testing.T, ctx oidc.Context) {
				if _, err := ctx.ClientCert(); err == nil {
					t.Fatal("ClientCert() error = nil, want non-nil by default")
				}

				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return &x509.Certificate{}, nil
				}
				cert, err := ctx.ClientCert()
				if err != nil {
					t.Fatalf("ClientCert() error = %v", err)
				}
				if cert == nil {
					t.Fatal("ClientCert() returned nil certificate")
				}
			},
		},
		{
			name: "validate initial access token",
			run: func(t *testing.T, ctx oidc.Context) {
				if err := ctx.ValidateInitalAccessToken("token"); err != nil {
					t.Fatalf("ValidateInitalAccessToken() error = %v", err)
				}

				ctx.DCRValidateInitialTokenFunc = func(context.Context, string) error {
					return errors.New("error")
				}
				if err := ctx.ValidateInitalAccessToken("token"); err == nil {
					t.Fatal("ValidateInitalAccessToken() error = nil, want non-nil")
				}
			},
		},
		{
			name: "check jti",
			run: func(t *testing.T, ctx oidc.Context) {
				if err := ctx.CheckJTI("jti"); err != nil {
					t.Fatalf("CheckJTI() error = %v", err)
				}

				ctx.CheckJTIFunc = func(context.Context, string) error {
					return errors.New("error")
				}
				if err := ctx.CheckJTI("jti"); err == nil {
					t.Fatal("CheckJTI() error = nil, want non-nil")
				}
			},
		},
		{
			name: "render error",
			run: func(t *testing.T, ctx oidc.Context) {
				err := errors.New("error")
				if got := ctx.RenderError(err); !errors.Is(got, err) {
					t.Fatalf("RenderError() = %v, want %v", got, err)
				}

				ctx.RenderErrorFunc = func(http.ResponseWriter, *http.Request, error) error {
					return nil
				}
				if err := ctx.RenderError(errors.New("error")); err != nil {
					t.Fatalf("RenderError() error = %v", err)
				}
			},
		},
		{
			name: "rar compare auth details",
			run: func(t *testing.T, ctx oidc.Context) {
				called := false
				ctx.RARCompareDetailsFunc = func(_ context.Context, requested, granted []goidc.AuthDetail) error {
					called = true
					if requested != nil || granted != nil {
						t.Fatal("RARCompareAuthDetails() passed unexpected values")
					}
					return nil
				}
				if err := ctx.RARCompareAuthDetails(nil, nil); err != nil {
					t.Fatalf("RARCompareAuthDetails() error = %v", err)
				}
				if !called {
					t.Fatal("RARCompareAuthDetails() did not call RARCompareDetailsFunc")
				}
			},
		},
		{
			name: "ciba handle session",
			run: func(t *testing.T, ctx oidc.Context) {
				if err := ctx.CIBAHandleSession(nil, nil); err == nil {
					t.Fatal("CIBAHandleSession() error = nil, want non-nil by default")
				}

				ctx.CIBAHandleSessionFunc = func(context.Context, *goidc.AuthnSession, *goidc.Client) error {
					return nil
				}
				if err := ctx.CIBAHandleSession(nil, nil); err != nil {
					t.Fatalf("CIBAHandleSession() error = %v", err)
				}
			},
		},
		{
			name: "refresh token should issue",
			run: func(t *testing.T, ctx oidc.Context) {
				client := &goidc.Client{}
				grant := &goidc.Grant{}

				if !ctx.RefreshTokenShouldIssue(client, grant) {
					t.Fatal("RefreshTokenShouldIssue() = false, want true by default")
				}

				ctx.RefreshTokenShouldIssueFunc = func(context.Context, *goidc.Client, *goidc.Grant) bool {
					return false
				}
				if ctx.RefreshTokenShouldIssue(client, grant) {
					t.Fatal("RefreshTokenShouldIssue() = true, want false")
				}
			},
		},
		{
			name: "handle grant",
			run: func(t *testing.T, ctx oidc.Context) {
				if err := ctx.HandleGrant(&goidc.Grant{}); err != nil {
					t.Fatalf("HandleGrant() error = %v", err)
				}

				ctx.HandleGrantFunc = func(context.Context, *goidc.Grant) error {
					return errors.New("error")
				}
				if err := ctx.HandleGrant(&goidc.Grant{}); err == nil {
					t.Fatal("HandleGrant() error = nil, want non-nil")
				}
			},
		},
		{
			name: "http client",
			run: func(t *testing.T, ctx oidc.Context) {
				custom := &http.Client{}
				ctx.HTTPClientFunc = func(context.Context) *http.Client {
					return custom
				}
				if got := ctx.HTTPClient(); got != custom {
					t.Fatal("HTTPClient() did not return the configured client")
				}
			},
		},
		{
			name: "pairwise subject",
			run: func(t *testing.T, ctx oidc.Context) {
				client := &goidc.Client{
					ClientMeta: goidc.ClientMeta{
						SubIdentifierType:   goidc.SubIdentifierPairwise,
						SectorIdentifierURI: "https://example.com",
					},
				}

				if got := ctx.PairwiseSubject("sub", client); got != "sub" {
					t.Fatalf("PairwiseSubject() = %q, want %q", got, "sub")
				}

				ctx.PairwiseSubjectFunc = func(_ context.Context, sub string, client *goidc.Client) string {
					parsedURL, _ := url.Parse(client.SectorIdentifierURI)
					return parsedURL.Hostname() + "_" + sub
				}
				if got := ctx.PairwiseSubject("random_sub", client); got != "example.com_random_sub" {
					t.Fatalf("PairwiseSubject() = %q, want %q", got, "example.com_random_sub")
				}
			},
		},
		{
			name: "generated values delegate to funcs",
			run: func(t *testing.T, ctx oidc.Context) {
				grant := &goidc.Grant{ID: "grant_id"}
				ctx.GrantIDFunc = func(context.Context) string { return "grant" }
				ctx.JWTIDFunc = func(context.Context) string { return "jwt" }
				ctx.AuthCodeFunc = func(context.Context) string { return "code" }
				ctx.RefreshTokenFunc = func(context.Context) string { return "refresh" }
				ctx.OpaqueTokenFunc = func(context.Context, *goidc.Grant) string { return "opaque_" + grant.ID }

				if got := ctx.GrantID(); got != "grant" {
					t.Fatalf("GrantID() = %q, want %q", got, "grant")
				}
				if got := ctx.JWTID(); got != "jwt" {
					t.Fatalf("JWTID() = %q, want %q", got, "jwt")
				}
				if got := ctx.AuthCode(); got != "code" {
					t.Fatalf("AuthCode() = %q, want %q", got, "code")
				}
				if got := ctx.RefreshToken(); got != "refresh" {
					t.Fatalf("RefreshToken() = %q, want %q", got, "refresh")
				}
				if got := ctx.OpaqueToken(grant); got != "opaque_grant_id" {
					t.Fatalf("OpaqueToken() = %q, want %q", got, "opaque_grant_id")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.run(t, oidctest.NewContext(t))
		})
	}
}

func TestSign(t *testing.T) {
	ctx := oidctest.NewContext(t)
	jwks, err := ctx.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	jwk := jwks.Keys[0]

	jws, err := ctx.Sign(map[string]any{"claim": "value"}, goidc.SignatureAlgorithm(jwk.Algorithm), nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parsedJWS, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.PS256})
	if err != nil {
		t.Fatalf("jwt.ParseSigned() error = %v", err)
	}

	var claims map[string]any
	if err := parsedJWS.Claims(jwk.Public().Key, &claims); err != nil {
		t.Fatalf("parsedJWS.Claims() error = %v", err)
	}
	if claims["claim"] != "value" {
		t.Fatalf("claims[claim] = %v, want %q", claims["claim"], "value")
	}
}

func TestSignWithSignerFunc(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			SignerFunc: func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
				return "random_key_id", testSigner{signer: signingKey}, nil
			},
		},
	}

	jws, err := ctx.Sign(map[string]any{goidc.ClaimSubject: "random@email.com"}, goidc.RS256, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parsedJWS, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.RS256})
	if err != nil {
		t.Fatalf("jwt.ParseSigned() error = %v", err)
	}

	var claims map[string]any
	if err := parsedJWS.Claims(signingKey.Public(), &claims); err != nil {
		t.Fatalf("parsedJWS.Claims() error = %v", err)
	}
	if claims[goidc.ClaimSubject] != "random@email.com" {
		t.Fatalf("claims[sub] = %v, want %q", claims[goidc.ClaimSubject], "random@email.com")
	}
}

func TestDecryptWithDecrypterFunc(t *testing.T) {
	encKey := oidctest.PrivateRSAOAEP256JWK(t, "enc_key")
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			DecrypterFunc: func(context.Context, string, goidc.KeyEncryptionAlgorithm) (crypto.Decrypter, error) {
				return encKey.Key.(crypto.Decrypter), nil
			},
		},
	}

	jwe, err := joseutil.Encrypt("random_jws", encKey.Public(), goidc.A128CBC_HS256)
	if err != nil {
		t.Fatalf("joseutil.Encrypt() error = %v", err)
	}

	jws, err := ctx.Decrypt(
		jwe,
		[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256},
		[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
	)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if jws != "random_jws" {
		t.Fatalf("Decrypt() = %q, want %q", jws, "random_jws")
	}
}

func newContext() oidc.Context {
	return oidc.Context{
		Configuration: &oidc.Configuration{},
		Request:       httptest.NewRequest(http.MethodGet, "https://example.com", nil),
		Response:      httptest.NewRecorder(),
	}
}

type testSigner struct {
	signer *rsa.PrivateKey
}

func (s testSigner) Public() crypto.PublicKey {
	return s.signer.PublicKey
}

func (s testSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signer.Sign(rand, digest, opts)
}
