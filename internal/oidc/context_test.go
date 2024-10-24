package oidc_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestTokenAuthnSigAlgs(t *testing.T) {

	// Given.
	testCases := []struct {
		ctx     oidc.Context
		sigAlgs []jose.SignatureAlgorithm
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
					PrivateKeyJWTSigAlgs: []jose.SignatureAlgorithm{jose.PS256},
				},
			},
			sigAlgs: []jose.SignatureAlgorithm{jose.PS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnSecretJWT,
					},
					ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS256},
				},
			},
			sigAlgs: []jose.SignatureAlgorithm{jose.HS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					TokenAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnPrivateKeyJWT,
						goidc.ClientAuthnSecretJWT,
					},
					PrivateKeyJWTSigAlgs:   []jose.SignatureAlgorithm{jose.PS256},
					ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS256},
				},
			},
			sigAlgs: []jose.SignatureAlgorithm{jose.PS256, jose.HS256},
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
		sigAlgs []jose.SignatureAlgorithm
	}{
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					PrivateKeyJWTSigAlgs:   []jose.SignatureAlgorithm{jose.PS256},
					ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS256},
				},
			},
			sigAlgs: nil,
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					PrivateKeyJWTSigAlgs:   []jose.SignatureAlgorithm{jose.PS256},
					ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS256},
					TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnPrivateKeyJWT,
					},
				},
			},
			sigAlgs: []jose.SignatureAlgorithm{jose.PS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					PrivateKeyJWTSigAlgs:   []jose.SignatureAlgorithm{jose.PS256},
					ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS256},
					TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnSecretJWT,
					},
				},
			},
			sigAlgs: []jose.SignatureAlgorithm{jose.HS256},
		},
		{
			ctx: oidc.Context{
				Configuration: &oidc.Configuration{
					PrivateKeyJWTSigAlgs:   []jose.SignatureAlgorithm{jose.PS256},
					ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS256},
					TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{
						goidc.ClientAuthnPrivateKeyJWT,
						goidc.ClientAuthnSecretJWT,
					},
				},
			},
			sigAlgs: []jose.SignatureAlgorithm{jose.PS256, jose.HS256},
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
	ctx.HandleDynamicClientFunc = func(r *http.Request, clientInfo *goidc.ClientMetaInfo) error {
		clientInfo.TokenAuthnMethod = goidc.ClientAuthnNone
		return nil
	}
	clientInfo := &goidc.ClientMetaInfo{}

	// When.
	err := ctx.HandleDynamicClient(clientInfo)

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
	clientInfo := &goidc.ClientMetaInfo{}
	// When.
	err := ctx.HandleDynamicClient(clientInfo)
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
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey, encryptionKey}}

	// When.
	algs := ctx.SigAlgs()

	// Then.
	want := []jose.SignatureAlgorithm{jose.PS256}
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
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	// When.
	publicJWKS := ctx.PublicKeys()

	// Then.
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
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	// When.
	publicJWK, ok := ctx.PublicKey("signing_key")

	// Then.
	if !ok {
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
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	// When.
	privateJWK, ok := ctx.PrivateKey("signing_key")

	// Then.
	if !ok {
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
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}

	// When.
	_, ok := ctx.PrivateKey("signing_key")

	// Then.
	if ok {
		t.Error("a key was found, but none should be")
	}
}

func TestUserInfoSigKeyForClient(t *testing.T) {
	// Given.
	keyID := "signing_key"
	signingKey := oidctest.PrivatePS256JWK(t, keyID, goidc.KeyUsageSignature)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.UserDefaultSigAlg = jose.SignatureAlgorithm(signingKey.Algorithm)
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	client := &goidc.Client{}

	// When.
	jwk, ok := ctx.UserInfoSigKeyForClient(client)

	// Then.
	if !ok {
		t.Fatalf("the key should be found")
	}

	if jwk.KeyID != keyID {
		t.Errorf("KeyID = %s, want %s", jwk.KeyID, keyID)
	}
}

func TestUserInfoSigKeyForClient_ClientWithDefaultAlgorithm(t *testing.T) {
	// Given.
	defaultKey := oidctest.PrivatePS256JWK(t, "default_key", goidc.KeyUsageSignature)
	alternativeKey := oidctest.PrivateRS256JWK(t, "alternative_key", goidc.KeyUsageSignature)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.PrivateJWKS = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{defaultKey, alternativeKey},
	}
	ctx.UserDefaultSigAlg = jose.SignatureAlgorithm(defaultKey.Algorithm)
	ctx.UserSigAlgs = []jose.SignatureAlgorithm{
		jose.SignatureAlgorithm(defaultKey.Algorithm),
		jose.SignatureAlgorithm(alternativeKey.Algorithm),
	}

	client := &goidc.Client{}
	client.UserInfoSigAlg = jose.RS256

	// When.
	jwk, ok := ctx.UserInfoSigKeyForClient(client)

	// Then.
	if !ok {
		t.Fatalf("the key should be found")
	}

	if jwk.KeyID != alternativeKey.KeyID {
		t.Errorf("KeyID = %s, want %s", jwk.KeyID, alternativeKey.KeyID)
	}
}

func TestIDTokenSigKeyForClient(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.UserDefaultSigAlg = jose.SignatureAlgorithm(signingKey.Algorithm)
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	client := &goidc.Client{}

	// When.
	jwk, ok := ctx.IDTokenSigKeyForClient(client)

	// Then.
	if !ok {
		t.Fatalf("the key should be found")
	}

	if jwk.KeyID != signingKey.KeyID {
		t.Errorf("KeyID = %s, want %s", jwk.KeyID, signingKey.KeyID)
	}
}

func TestIDTokenSigKeyForClient_ClientWithDefaultAlgorithm(t *testing.T) {
	// Given.
	defaultKey := oidctest.PrivatePS256JWK(t, "default_key", goidc.KeyUsageSignature)
	alternativeKey := oidctest.PrivateRS256JWK(t, "alternative_key", goidc.KeyUsageSignature)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.PrivateJWKS = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{defaultKey, alternativeKey},
	}
	ctx.UserDefaultSigAlg = jose.SignatureAlgorithm(defaultKey.Algorithm)
	ctx.UserSigAlgs = []jose.SignatureAlgorithm{
		jose.SignatureAlgorithm(defaultKey.Algorithm),
		jose.SignatureAlgorithm(alternativeKey.Algorithm),
	}

	client := &goidc.Client{}
	client.IDTokenSigAlg = jose.RS256

	// When.
	jwk, ok := ctx.IDTokenSigKeyForClient(client)

	// Then.
	if !ok {
		t.Fatalf("the key should be found")
	}

	if jwk.KeyID != alternativeKey.KeyID {
		t.Errorf("KeyID = %s, want %s", jwk.KeyID, alternativeKey.KeyID)
	}
}

func TestJARMSigKeyForClient_HappyPath(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key", goidc.KeyUsageSignature)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.JARMDefaultSigAlg = jose.SignatureAlgorithm(signingKey.Algorithm)
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	client := &goidc.Client{}

	// When.
	jwk, ok := ctx.JARMSigKeyForClient(client)

	// Then.
	if !ok {
		t.Fatalf("the key should be found")
	}

	if jwk.KeyID != signingKey.KeyID {
		t.Errorf("KeyID = %s, want %s", jwk.KeyID, signingKey.KeyID)
	}
}

func TestJARMSigKeyForClient_ClientWithDefaultAlgorithm(t *testing.T) {
	// Given.
	defaultKey := oidctest.PrivatePS256JWK(t, "default_key", goidc.KeyUsageSignature)
	alternativeKey := oidctest.PrivateRS256JWK(t, "alternative_key", goidc.KeyUsageSignature)

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{},
	}
	ctx.PrivateJWKS = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{defaultKey, alternativeKey},
	}
	ctx.JARMSigAlgs = []jose.SignatureAlgorithm{
		jose.SignatureAlgorithm(defaultKey.Algorithm),
		jose.SignatureAlgorithm(alternativeKey.Algorithm),
	}

	client := &goidc.Client{}
	client.JARMSigAlg = jose.RS256

	// When.
	jwk, ok := ctx.JARMSigKeyForClient(client)

	// Then.
	if !ok {
		t.Fatalf("the key should be found")
	}

	if jwk.KeyID != alternativeKey.KeyID {
		t.Errorf("KeyID = %s, want %s", jwk.KeyID, alternativeKey.KeyID)
	}
}
