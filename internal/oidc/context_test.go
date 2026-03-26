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
					TokenAuthnMethods: []goidc.AuthnMethod{},
				},
			},
			sigAlgs: nil,
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.AuthnMethod{
						goidc.AuthnMethodPrivateKeyJWT,
					},
					PrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
				},
			},
			sigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.AuthnMethod{
						goidc.AuthnMethodSecretJWT,
					},
					ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
				},
			},
			sigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.AuthnMethod{
						goidc.AuthnMethodPrivateKeyJWT,
						goidc.AuthnMethodSecretJWT,
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
					TokenIntrospectionAuthnMethods: []goidc.AuthnMethod{
						goidc.AuthnMethodPrivateKeyJWT,
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
					TokenIntrospectionAuthnMethods: []goidc.AuthnMethod{
						goidc.AuthnMethodSecretJWT,
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
					TokenIntrospectionAuthnMethods: []goidc.AuthnMethod{
						goidc.AuthnMethodPrivateKeyJWT,
						goidc.AuthnMethodSecretJWT,
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
	ctx.DCRHandleClientFunc = func(_ context.Context, id string, meta *goidc.ClientMeta) error {
		meta.TokenAuthnMethod = goidc.AuthnMethodNone
		return nil
	}
	clientInfo := &goidc.ClientMeta{}

	// When.
	err := ctx.HandleDynamicClient("random_id", clientInfo)

	// Then.
	if err != nil {
		t.Errorf("no error was expected: %v", err)
	}

	if clientInfo.TokenAuthnMethod != goidc.AuthnMethodNone {
		t.Errorf("AuthnMethod = %s, want %s", clientInfo.TokenAuthnMethod, goidc.AuthnMethodNone)
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

func TestPairwiseSubject(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			PairwiseSubjectFunc: func(ctx context.Context, sub string, client *goidc.Client) string {
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
	sub := ctx.PairwiseSubject("random_sub", client)

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
	ctx.IsClientAllowedTokenIntrospectionFunc = func(_ context.Context, c *goidc.Client, _ goidc.TokenInfo) bool {
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
	ctx.IsClientAllowedTokenRevocationFunc = func(_ context.Context, c *goidc.Client) bool {
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
	ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
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
	ctx.DCRValidateInitialTokenFunc = func(ctx context.Context, s string) error {
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
	err := ctx.RARCompareAuthDetails(nil, nil)
	// Then.
	if err == nil {
		t.Error("the default behavior is to return an error")
	}

	// Given.
	ctx.RARCompareDetailsFunc = func(_ context.Context, granted, requested []goidc.AuthDetail) error {
		return nil
	}
	// When.
	err = ctx.RARCompareAuthDetails(nil, nil)
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
	err := ctx.CIBAHandleSession(nil, nil)
	// Then.
	if err == nil {
		t.Error("the default behavior is to return an error")
	}

	// Given.
	ctx.CIBAHandleSessionFunc = func(ctx context.Context, as *goidc.AuthnSession, c *goidc.Client) error {
		return nil
	}
	// When.
	err = ctx.CIBAHandleSession(nil, nil)
	// Then.
	if err != nil {
		t.Fatal("no error should be returned")
	}
}

func TestShouldIssueRefreshToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client := &goidc.Client{}
	grant := &goidc.Grant{}

	// When.
	should := ctx.ShouldIssueRefreshToken(client, grant)

	// Then.
	if !should {
		t.Error("the default behavior is to return true")
	}

	// Given.
	ctx.ShouldIssueRefreshTokenFunc = func(_ context.Context, _ *goidc.Client, _ *goidc.Grant) bool {
		return false
	}

	// When.
	should = ctx.ShouldIssueRefreshToken(client, grant)

	// Then.
	if should {
		t.Error("the refresh token should be not allowed")
	}

}

func TestHandleGrant(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	grant := &goidc.Grant{}

	// When.
	err := ctx.HandleGrant(grant)

	// Then.
	if err != nil {
		t.Error("the default behavior is to return nil")
	}

	// Given.
	ctx.HandleGrantFunc = func(context.Context, *goidc.Grant) error {
		return errors.New("error")
	}

	// When.
	err = ctx.HandleGrant(grant)

	// Then.
	if err == nil {
		t.Error("an error should be returned")
	}
}

func TestHTTPClient(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.HTTPClientFunc = nil

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
