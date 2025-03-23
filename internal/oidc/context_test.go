package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
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

	// Given.
	testCases := []struct {
		ctx     oidc.Context
		sigAlgs []goidc.SignatureAlgorithm
	}{
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.ClientAuthnType{},
				},
			},
			sigAlgs: nil,
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnPrivateKeyJWT,
					},
					PrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
				},
			},
			sigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnSecretJWT,
					},
					ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
				},
			},
			sigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnPrivateKeyJWT,
						goidc.ClientAuthnSecretJWT,
					},
					PrivateKeyJWTSigAlgs:   []goidc.SignatureAlgorithm{goidc.PS256},
					ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
				},
			},
			sigAlgs: []goidc.SignatureAlgorithm{goidc.PS256, goidc.HS256},
		},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				// When.
				sigAlgs := testCase.ctx.TokenAuthnSigAlgs()

				// Then.
				if !cmp.Equal(sigAlgs, testCase.sigAlgs, cmpopts.EquateEmpty()) {
					t.Errorf("ClientAuthnSigAlgs() = %v, want %v", sigAlgs, testCase.sigAlgs)
				}
			},
		)
	}
}

func TestIntrospectionClientAuthnSigAlgs(t *testing.T) {

	// Given.
	testCases := []struct {
		ctx     oidc.Context
		sigAlgs []goidc.SignatureAlgorithm
	}{
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					PrivateKeyJWTSigAlgs:   []goidc.SignatureAlgorithm{goidc.PS256},
					ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
				},
			},
			sigAlgs: nil,
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					PrivateKeyJWTSigAlgs:   []goidc.SignatureAlgorithm{goidc.PS256},
					ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
					TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnPrivateKeyJWT,
					},
				},
			},
			sigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					PrivateKeyJWTSigAlgs:   []goidc.SignatureAlgorithm{goidc.PS256},
					ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
					TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnSecretJWT,
					},
				},
			},
			sigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					PrivateKeyJWTSigAlgs:   []goidc.SignatureAlgorithm{goidc.PS256},
					ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
					TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnPrivateKeyJWT,
						goidc.ClientAuthnSecretJWT,
					},
				},
			},
			sigAlgs: []goidc.SignatureAlgorithm{goidc.PS256, goidc.HS256},
		},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %d", i),
			func(t *testing.T) {
				// When.
				sigAlgs := testCase.ctx.TokenIntrospectionAuthnSigAlgs()

				// Then.
				if !cmp.Equal(sigAlgs, testCase.sigAlgs, cmpopts.EquateEmpty()) {
					t.Errorf("IntrospectionClientAuthnSigAlgs() = %v, want %v", sigAlgs, testCase.sigAlgs)
				}
			},
		)
	}
}

func TestHandleDynamicClient(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.HandleDynamicClientFunc = func(r *http.Request, id string, meta *goidc.ClientMeta) error {
		meta.TokenAuthnMethod = goidc.ClientAuthnNone
		return nil
	}
	clientInfo := &goidc.ClientMeta{}

	// When.
	err := ctx.HandleDynamicClient("random_id", clientInfo)

	// Then.
	if err != nil {
		t.Errorf("no error was expected: %v", err)
	}

	if clientInfo.TokenAuthnMethod != goidc.ClientAuthnNone {
		t.Errorf("AuthnMethod = %s, want %s", clientInfo.TokenAuthnMethod, goidc.ClientAuthnNone)
	}
}

func TestHandleDynamicClient_HandlerIsNil(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	clientInfo := &goidc.ClientMeta{}
	// When.
	err := ctx.HandleDynamicClient("random_id", clientInfo)
	// Then.
	if err != nil {
		t.Errorf("no error was expected: %v", err)
	}
}

func TestGetAudiences(t *testing.T) {
	// Given.
	host := "https://example.com"
	ctx := oidc.Context{
		Request: httptest.NewRequest(http.MethodPost, "/userinfo", nil),
		Configuration: &oidc.Configuration{
			Host:          host,
			EndpointToken: "/token",
		},
	}

	// When.
	auds := ctx.AssertionAudiences()

	// Then.
	wantedAuds := []string{host, host + "/token", host + "/userinfo"}
	if !cmp.Equal(auds, wantedAuds) {
		t.Errorf("Audiences() = %v, want %v", auds, wantedAuds)
	}
}

func TestGetAudiences_MTLSIsEnabled(t *testing.T) {
	// Given.
	host := "https://example.com"
	mtlsHost := "https://matls-example.com"
	ctx := oidc.Context{
		Request: httptest.NewRequest(http.MethodPost, "/userinfo", nil),
		Configuration: &oidc.Configuration{
			Host:          host,
			MTLSIsEnabled: true,
			MTLSHost:      mtlsHost,
			EndpointToken: "/token",
		},
	}

	// When.
	auds := ctx.AssertionAudiences()

	// Then.
	wantedAuds := []string{host, host + "/token", host + "/userinfo",
		mtlsHost + "/token", mtlsHost + "/userinfo"}
	if !cmp.Equal(auds, wantedAuds) {
		t.Errorf("Audiences() = %v, want %v", auds, wantedAuds)
	}
}

func TestPolicy(t *testing.T) {
	// Given.
	policyID := "random_policy_id"
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Policies = append(ctx.Policies, goidc.NewPolicy(policyID, nil, nil))

	// When.
	policy := ctx.Policy(policyID)

	// Then.
	if policy.ID != policyID {
		t.Errorf("ID = %s, want %s", policy.ID, policyID)
	}
}

func TestAvailablePolicy(t *testing.T) {
	// Given.
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(r *http.Request, c *goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	availablePolicy := goidc.NewPolicy(
		"available_policy",
		func(r *http.Request, c *goidc.Client, s *goidc.AuthnSession) bool {
			return true
		},
		nil,
	)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy, availablePolicy}

	// When.
	policy, ok := ctx.AvailablePolicy(&goidc.Client{}, &goidc.AuthnSession{})

	// Then.
	if !ok {
		t.Errorf("no policy was found available, but the one with id %s should be", availablePolicy.ID)
	}

	if policy.ID != availablePolicy.ID {
		t.Errorf("ID = %s, want %s", policy.ID, availablePolicy.ID)
	}
}

func TestAvailablePolicy_NoPolicyAvailable(t *testing.T) {
	// Given.
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(r *http.Request, c *goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy}

	// When.
	policy, ok := ctx.AvailablePolicy(&goidc.Client{}, &goidc.AuthnSession{})

	// Then.
	if ok {
		t.Errorf("no policy is available, but one was found %s", policy.ID)
	}
}

func TestBaseURL(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Host = "https://example.com"
	ctx.EndpointPrefix = "/auth"

	// When.
	baseURL := ctx.BaseURL()

	// Then.
	if baseURL != "https://example.com/auth" {
		t.Errorf("BaseURL() = %s, want %s", baseURL, "https://example.com/auth")
	}
}

func TestMTLSBaseURL(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.MTLSHost = "https://matls-example.com"
	ctx.EndpointPrefix = "/auth"

	// When.
	baseURL := ctx.MTLSBaseURL()

	// Then.
	if baseURL != "https://matls-example.com/auth" {
		t.Errorf("MTLSBaseURL() = %s, want %s", baseURL, "https://matls-example.com/auth")
	}
}

func TestBearerToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	ctx.Request.Header.Set("Authorization", "Bearer access_token")

	// When.
	token, ok := ctx.BearerToken()

	// Then.
	if !ok {
		t.Fatal("a bearer token is present in the request, but was not found")
	}

	if token != "access_token" {
		t.Errorf("BearerToken() = %s, want %s", token, "access_token")
	}
}

func TestBearerToken_NoToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://example.com", nil)

	// When.
	token, ok := ctx.BearerToken()

	// Then.
	if ok {
		t.Fatalf("a bearer token was not informed, but found %s", token)
	}
}

func TestBearerToken_NotABearerToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	ctx.Request.Header.Set("Authorization", "DPoP token")

	// When.
	token, ok := ctx.BearerToken()

	// Then.
	if ok {
		t.Fatalf("a bearer token was not informed, but found %s", token)
	}
}

func TestAuthorizationToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	ctx.Request.Header.Set("Authorization", "Bearer access_token")

	// When.
	token, tokenType, ok := ctx.AuthorizationToken()

	// Then.
	if !ok {
		t.Fatal("a token is present in the request, but was not found")
	}

	if token != "access_token" {
		t.Errorf("AuthorizationToken() = %s, want %s", token, "access_token")
	}

	if tokenType != goidc.TokenTypeBearer {
		t.Errorf("AuthorizationToken() = %s, want %s", tokenType, goidc.TokenTypeBearer)
	}
}

func TestAuthorizationToken_NoToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://example.com", nil)

	// When.
	token, tokenType, ok := ctx.AuthorizationToken()

	// Then.
	if ok {
		t.Fatalf("a bearer token was not informed, but found %s with type %s", token, tokenType)
	}
}

func TestHeader(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.Request = httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	ctx.Request.Header.Set("Test-Header", "test_value")

	// When.
	header, ok := ctx.Header("Test-Header")

	// Then.
	if !ok {
		t.Fatal("the header was informed, but was not found")
	}

	if header != "test_value" {
		t.Fatalf("Header() = %s, want %s", header, "test_value")
	}
}

func TestSigAlgs(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)
	encryptionKey := oidctest.PrivatePS256JWK(t, "encryption_key", goidc.KeyUsageEncryption)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey, encryptionKey}}, nil
	}

	// When.
	algs, err := ctx.SigAlgs()

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	want := []goidc.SignatureAlgorithm{goidc.PS256}
	if !cmp.Equal(algs, want) {
		t.Errorf("SignatureAlgorithms() = %s, want %s", algs, want)
	}
}

func TestPublicKeys_HappyPath(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}, nil
	}

	// When.
	publicJWKS, err := ctx.PublicJWKS()

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if len(publicJWKS.Keys) != 1 {
		t.Fatalf("len(Keys) = %d, want 1. jwks: %v", len(publicJWKS.Keys), publicJWKS)
	}

	publicJWK := publicJWKS.Keys[0]
	if publicJWK.KeyID != signingKey.KeyID {
		t.Errorf("KeyID = %s, want %s", publicJWK.KeyID, signingKey.KeyID)
	}

	if !publicJWK.IsPublic() {
		t.Error("the jwk found is not public")
	}
}

func TestPublicKey_HappyPath(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}, nil
	}

	// When.
	publicJWK, err := ctx.PublicJWK("signing_key")

	// Then.
	if err != nil {
		t.Fatalf("no jwk found")
	}

	if publicJWK.KeyID != signingKey.KeyID {
		t.Errorf("KeyID = %s, want %s", publicJWK.KeyID, signingKey.KeyID)
	}

	if !publicJWK.IsPublic() {
		t.Error("the jwk found is not public")
	}
}

func TestPrivateKey_HappyPath(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{signingKey}}, nil
	}

	// When.
	privateJWK, err := ctx.JWK("signing_key")

	// Then.
	if err != nil {
		t.Fatalf("no jwk found")
	}

	if privateJWK.KeyID != signingKey.KeyID {
		t.Errorf("KeyID = %s, want %s", privateJWK.KeyID, signingKey.KeyID)
	}

	if privateJWK.IsPublic() {
		t.Error("the jwk found is public")
	}
}

func TestPrivateKey_KeyDoesntExist(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{}}, nil
	}

	// When.
	_, err := ctx.JWK("signing_key")

	// Then.
	if err == nil {
		t.Error("a key was found, but none should be")
	}
}

func TestExportableSubject(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			GeneratePairwiseSubIDFunc: func(ctx context.Context, sub string, client *goidc.Client) string {
				parseURL, _ := url.Parse(client.SectorIdentifierURI)
				return parseURL.Hostname() + "_" + sub
			},
		},
	}
	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			SubIdentifierType:   goidc.SubIdentifierPairwise,
			SectorIdentifierURI: "https://example.com",
		},
	}

	// When.
	sub := ctx.ExportableSubject("random_sub", client)

	// Then.
	if sub != "example.com_random_sub" {
		t.Errorf("got %s, want = %s", sub, "example.com_random_sub")
	}
}

func TestExportableSubject_PairwiseAsDefault(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			DefaultSubIdentifierType: goidc.SubIdentifierPairwise,
			GeneratePairwiseSubIDFunc: func(ctx context.Context, sub string, client *goidc.Client) string {
				parseURL, _ := url.Parse(client.SectorIdentifierURI)
				return parseURL.Hostname() + "_" + sub
			},
		},
	}
	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			SectorIdentifierURI: "https://example.com",
		},
	}

	// When.
	sub := ctx.ExportableSubject("random_sub", client)

	// Then.
	if sub != "example.com_random_sub" {
		t.Errorf("got %s, want = %s", sub, "example.com_random_sub")
	}
}

func TestIsClientAllowedTokenIntrospection(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	client := &goidc.Client{}
	info := goidc.TokenInfo{}
	// When.
	isAllowed := ctx.IsClientAllowedTokenIntrospection(client, info)
	// Then.
	if isAllowed {
		t.Error("the default behavior should be to not allow introspection")
	}

	// Given.
	ctx.IsClientAllowedTokenIntrospectionFunc = func(c *goidc.Client, _ goidc.TokenInfo) bool {
		return true
	}
	// When.
	isAllowed = ctx.IsClientAllowedTokenIntrospection(client, info)
	// Then.
	if !isAllowed {
		t.Errorf("got %t, want %t", isAllowed, true)
	}
}

func TestIsClientAllowedTokenRevocationFunc(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	client := &goidc.Client{}
	// When.
	isAllowed := ctx.IsClientAllowedTokenRevocation(client)
	// Then.
	if isAllowed {
		t.Error("the default behavior should be to not allow revocation")
	}

	// Given.
	ctx.IsClientAllowedTokenRevocationFunc = func(c *goidc.Client) bool {
		return true
	}
	// When.
	isAllowed = ctx.IsClientAllowedTokenRevocation(client)
	// Then.
	if !isAllowed {
		t.Errorf("got %t, want %t", isAllowed, true)
	}
}

func TestClientCert(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	// When.
	_, err := ctx.ClientCert()
	// Then.
	if err == nil {
		t.Error("the default behavior is to return an error")
	}

	// Given.
	ctx.ClientCertFunc = func(r *http.Request) (*x509.Certificate, error) {
		return &x509.Certificate{}, nil
	}
	// When.
	cert, err := ctx.ClientCert()
	// Then.
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Error("the client certificate should not be nil")
	}
}

func TestValidateInitalAccessToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	// When.
	err := ctx.ValidateInitalAccessToken("random_token")
	// Then.
	if err != nil {
		t.Error("the default behavior is to return nil")
	}

	// Given.
	ctx.ValidateInitialAccessTokenFunc = func(r *http.Request, s string) error {
		return errors.New("error")
	}
	// When.
	err = ctx.ValidateInitalAccessToken("random_token")
	// Then.
	if err == nil {
		t.Fatal("an error should be returned")
	}
}

func TestCheckJTI(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	// When.
	err := ctx.CheckJTI("token_id")
	// Then.
	if err != nil {
		t.Error("the default behavior is to return nil")
	}

	// Given.
	ctx.CheckJTIFunc = func(ctx context.Context, s string) error {
		return errors.New("error")
	}
	// When.
	err = ctx.CheckJTI("token_id")
	// Then.
	if err == nil {
		t.Fatal("an error should be returned")
	}
}

func TestRenderError(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	// When.
	err := ctx.RenderError(errors.New("error"))
	// Then.
	if err == nil {
		t.Error("the default behavior is to return the error")
	}

	// Given.
	ctx.RenderErrorFunc = func(w http.ResponseWriter, r *http.Request, err error) error {
		return nil
	}
	// When.
	err = ctx.RenderError(errors.New("error"))
	// Then.
	if err != nil {
		t.Fatal("no error should be returned")
	}
}

func TestCompareAuthDetails(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	// When.
	err := ctx.CompareAuthDetails(nil, nil)
	// Then.
	if err == nil {
		t.Error("the default behavior is to return an error")
	}

	// Given.
	ctx.CompareAuthDetailsFunc = func(granted, requested []goidc.AuthorizationDetail) error {
		return nil
	}
	// When.
	err = ctx.CompareAuthDetails(nil, nil)
	// Then.
	if err != nil {
		t.Fatal("no error should be returned")
	}
}

func TestInitBackAuth(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	// When.
	err := ctx.InitBackAuth(nil)
	// Then.
	if err == nil {
		t.Error("the default behavior is to return an error")
	}

	// Given.
	ctx.InitBackAuthFunc = func(ctx context.Context, as *goidc.AuthnSession) error {
		return nil
	}
	// When.
	err = ctx.InitBackAuth(nil)
	// Then.
	if err != nil {
		t.Fatal("no error should be returned")
	}
}

func TestValidateBackAuth(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	// When.
	err := ctx.ValidateBackAuth(nil)
	// Then.
	if err == nil {
		t.Error("the default behavior is to return an error")
	}

	// Given.
	ctx.ValidateBackAuthFunc = func(ctx context.Context, as *goidc.AuthnSession) error {
		return nil
	}
	// When.
	err = ctx.ValidateBackAuth(nil)
	// Then.
	if err != nil {
		t.Fatal("no error should be returned")
	}
}

func TestShouldIssueRefreshToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	client := &goidc.Client{}
	grantInfo := goidc.GrantInfo{}

	// When.
	should := ctx.ShouldIssueRefreshToken(client, grantInfo)

	// Then.
	if should {
		t.Error("the default behavior is to return false")
	}

	// Given.
	ctx.ShouldIssueRefreshTokenFunc = func(c *goidc.Client, gi goidc.GrantInfo) bool {
		return true
	}
	client.GrantTypes = append(client.GrantTypes, goidc.GrantRefreshToken, goidc.GrantAuthorizationCode)
	grantInfo.GrantType = goidc.GrantAuthorizationCode

	// When.
	should = ctx.ShouldIssueRefreshToken(client, grantInfo)

	// Then.
	if !should {
		t.Error("the refresh token should be allowed")
	}

}

func TestShouldIssueRefreshToken_RefreshTokenNotAllowed(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			ShouldIssueRefreshTokenFunc: func(c *goidc.Client, gi goidc.GrantInfo) bool {
				return true
			},
		},
	}
	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			GrantTypes: []goidc.GrantType{goidc.GrantAuthorizationCode},
		},
	}
	grantInfo := goidc.GrantInfo{
		GrantType: goidc.GrantAuthorizationCode,
	}

	// When.
	should := ctx.ShouldIssueRefreshToken(client, grantInfo)

	// Then.
	if should {
		t.Error("the default behavior is to return false")
	}
}

func TestShouldIssueRefreshToken_ClientCredentialsGrant(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			ShouldIssueRefreshTokenFunc: func(c *goidc.Client, gi goidc.GrantInfo) bool {
				return true
			},
		},
	}
	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			GrantTypes: []goidc.GrantType{goidc.GrantRefreshToken, goidc.GrantClientCredentials},
		},
	}
	grantInfo := goidc.GrantInfo{
		GrantType: goidc.GrantClientCredentials,
	}

	// When.
	should := ctx.ShouldIssueRefreshToken(client, grantInfo)

	// Then.
	if should {
		t.Error("the default behavior is to return false")
	}
}

func TestTokenOptions_JWT(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			TokenOptionsFunc: func(gi goidc.GrantInfo, c *goidc.Client) goidc.TokenOptions {
				return goidc.NewJWTTokenOptions("random_key_id", 600)
			},
		},
	}
	client := &goidc.Client{}
	grantInfo := goidc.GrantInfo{}

	// When.
	opts := ctx.TokenOptions(grantInfo, client)

	// Then.
	if opts.Format != goidc.TokenFormatJWT {
		t.Errorf("got %s, want %s", opts.Format, goidc.TokenFormatJWT)
	}
}

func TestTokenOptions_Opaque(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			TokenOptionsFunc: func(gi goidc.GrantInfo, c *goidc.Client) goidc.TokenOptions {
				return goidc.NewOpaqueTokenOptions(30, 600)
			},
		},
	}
	client := &goidc.Client{}
	grantInfo := goidc.GrantInfo{}

	// When.
	opts := ctx.TokenOptions(grantInfo, client)

	// Then.
	if opts.Format != goidc.TokenFormatOpaque {
		t.Errorf("got %s, want %s", opts.Format, goidc.TokenFormatOpaque)
	}
}

func TestTokenOptions_OpaqueTokenCannotHaveRefreshTokenLength(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			TokenOptionsFunc: func(gi goidc.GrantInfo, c *goidc.Client) goidc.TokenOptions {
				return goidc.NewOpaqueTokenOptions(goidc.RefreshTokenLength, 600)
			},
		},
	}
	client := &goidc.Client{}
	grantInfo := goidc.GrantInfo{}

	// When.
	opts := ctx.TokenOptions(grantInfo, client)

	// Then.
	if opts.Format != goidc.TokenFormatOpaque {
		t.Errorf("got %s, want %s", opts.Format, goidc.TokenFormatOpaque)
	}

	if opts.OpaqueLength == goidc.RefreshTokenLength {
		t.Error("opaque tokens cannot have the same size as refresh tokens")
	}
}

func TestTokenOptions_JWTNotAllowedWhenPairwiseSubject(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			TokenOptionsFunc: func(gi goidc.GrantInfo, c *goidc.Client) goidc.TokenOptions {
				return goidc.NewJWTTokenOptions("random_key_id", 600)
			},
		},
	}
	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			SubIdentifierType: goidc.SubIdentifierPairwise,
		},
	}
	grantInfo := goidc.GrantInfo{}

	// When.
	opts := ctx.TokenOptions(grantInfo, client)

	// Then.
	if opts.Format != goidc.TokenFormatOpaque {
		t.Errorf("got %s, want %s", opts.Format, goidc.TokenFormatOpaque)
	}
}

func TestTokenOptions_JWTIsAllowedForPairwiseSubjectWhenClientCredentials(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			TokenOptionsFunc: func(gi goidc.GrantInfo, c *goidc.Client) goidc.TokenOptions {
				return goidc.NewJWTTokenOptions("random_key_id", 600)
			},
		},
	}
	client := &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			SubIdentifierType: goidc.SubIdentifierPairwise,
		},
	}
	grantInfo := goidc.GrantInfo{
		GrantType: goidc.GrantClientCredentials,
	}

	// When.
	opts := ctx.TokenOptions(grantInfo, client)

	// Then.
	if opts.Format != goidc.TokenFormatJWT {
		t.Errorf("got %s, want %s", opts.Format, goidc.TokenFormatJWT)
	}
}

func TestHandleGrant(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	grantInfo := goidc.GrantInfo{}

	// When.
	err := ctx.HandleGrant(&grantInfo)

	// Then.
	if err != nil {
		t.Error("the default behavior is to return nil")
	}

	// Given.
	ctx.HandleGrantFunc = func(r *http.Request, gi *goidc.GrantInfo) error {
		return errors.New("error")
	}

	// When.
	err = ctx.HandleGrant(&grantInfo)

	// Then.
	if err == nil {
		t.Error("an error should be returned")
	}
}

func TestHTTPClient(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}

	// When.
	httpClient := ctx.HTTPClient()

	// Then.
	if httpClient != http.DefaultClient {
		t.Error("the default behavior is to return the default http client")
	}

	// Given.
	ctx.HTTPClientFunc = func(ctx context.Context) *http.Client {
		return &http.Client{}
	}

	// When.
	httpClient = ctx.HTTPClient()

	// Then.
	if httpClient == http.DefaultClient {
		t.Error("a different client should be returned")
	}
}

func TestSign(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	jwks, _ := ctx.JWKS()
	jwk := jwks.Keys[0]
	claims := map[string]any{
		"claim": "value",
	}

	// When.
	jws, err := ctx.Sign(claims, goidc.SignatureAlgorithm(jwk.Algorithm), nil)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error signing the claims: %v", err)
	}

	parsedJWS, err := jwt.ParseSigned(jws, []goidc.SignatureAlgorithm{goidc.PS256})
	if err != nil {
		t.Fatalf("the jws is not valid: %v", err)
	}

	var parsedClaims map[string]any
	err = parsedJWS.Claims(jwk.Public().Key, &parsedClaims)
	if err != nil {
		t.Fatalf("the jws is not valid: %v", err)
	}

	if parsedClaims["claim"] != "value" {
		t.Errorf("claim = %v, want %s", parsedClaims["claim"], "value")
	}
}

func TestSign_WithSignerFunc(t *testing.T) {
	// Given.
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			SignerFunc: func(ctx context.Context, alg goidc.SignatureAlgorithm) (keyID string, signer crypto.Signer, err error) {
				return "random_key_id", testSigner{signer: signingKey}, nil
			},
		},
	}

	claims := map[string]any{
		goidc.ClaimSubject: "random@email.com",
	}

	// When.
	jws, err := ctx.Sign(claims, goidc.RS256, nil)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	parsedJWS, err := jwt.ParseSigned(
		jws,
		[]goidc.SignatureAlgorithm{goidc.RS256},
	)
	if err != nil {
		t.Fatalf("the jws is not valid: %v", err)
	}

	var parsedClaims map[string]any
	err = parsedJWS.Claims(signingKey.Public(), &parsedClaims)
	if err != nil {
		t.Fatalf("the jws is not valid: %v", err)
	}

	if parsedClaims[goidc.ClaimSubject] != "random@email.com" {
		t.Errorf("claim = %v, want %s", parsedClaims[goidc.ClaimSubject], "random@email.com")
	}
}

type testSigner struct {
	signer *rsa.PrivateKey
}

func (s testSigner) Public() crypto.PublicKey {
	return s.signer.PublicKey
}

func (s testSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.signer.Sign(rand, digest, opts)
}
func TestDecrypt_WithDecrypterFunc(t *testing.T) {
	// Given.
	encKey := oidctest.PrivateRSAOAEP256JWK(t, "enc_key")
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			DecrypterFunc: func(ctx context.Context, kid string, alg goidc.KeyEncryptionAlgorithm) (crypto.Decrypter, error) {
				return encKey.Key.(crypto.Decrypter), nil
			},
		},
	}

	jwe, err := joseutil.Encrypt("random_jws", encKey.Public(), goidc.A128CBC_HS256)
	if err != nil {
		t.Fatal(err)
	}

	// When.
	jws, err := ctx.Decrypt(jwe, []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256}, []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256})

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if jws != "random_jws" {
		t.Errorf("got %s, want random_jws", jws)
	}
}
