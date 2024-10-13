package provider

import (
	"context"
	"crypto/x509"
	"net/http"
	"slices"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestWithClientStorage(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	st := storage.NewClientManager()

	// When.
	err := WithClientStorage(st)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.ClientManager != st {
		t.Errorf("invalid client manager")
	}
}

func TestWithAuthnSessionStorage(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	st := storage.NewAuthnSessionManager()

	// When.
	err := WithAuthnSessionStorage(st)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthnSessionManager != st {
		t.Errorf("invalid session manager")
	}
}

func TestWithGrantSessionStorage(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	st := storage.NewGrantSessionManager()

	// When.
	err := WithGrantSessionStorage(st)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.GrantSessionManager != st {
		t.Errorf("invalid session manager")
	}
}

func TestWithPathPrefix(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithPathPrefix("/auth")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointPrefix: "/auth",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJWKSEndpoint(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJWKSEndpoint("/jwks")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointJWKS: "/jwks",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenEndpoint(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithTokenEndpoint("/token")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointToken: "/token",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthorizeEndpoint(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithAuthorizeEndpoint("/authorize")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointAuthorize: "/authorize",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPAREndpoint(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithPAREndpoint("/par")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointPushedAuthorization: "/par",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCREndpoint(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithDCREndpoint("/register")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointDCR: "/register",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEndpoint(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithUserInfoEndpoint("/userinfo")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointUserInfo: "/userinfo",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIntrospectionEndpoint(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithIntrospectionEndpoint("/introspect")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointIntrospection: "/introspect",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenRevocationEndpoint(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithTokenRevocationEndpoint("/revoke")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			EndpointTokenRevocation: "/revoke",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClaims(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithClaims("claim_one", "claim_two")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			Claims:     []string{"claim_one", "claim_two"},
			ClaimTypes: []goidc.ClaimType{goidc.ClaimTypeNormal},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClaimTypes(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithClaimTypes(goidc.ClaimTypeDistributed)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			ClaimTypes: []goidc.ClaimType{goidc.ClaimTypeDistributed},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoSignatureKeyIDs(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithUserInfoSignatureKeyIDs("sig_key")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			UserDefaultSigKeyID: "sig_key",
			UserSigKeyIDs:       []string{"sig_key"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIDTokenLifetime(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithIDTokenLifetime(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			IDTokenLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEncryption(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithUserInfoEncryption(jose.RSA_OAEP)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			UserEncIsEnabled: true,
			UserKeyEncAlgs:   []jose.KeyAlgorithm{jose.RSA_OAEP},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEncryption_NoAlgInformed(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithUserInfoEncryption(jose.RSA_OAEP_256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			UserEncIsEnabled: true,
			UserKeyEncAlgs:   []jose.KeyAlgorithm{jose.RSA_OAEP_256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithUserInfoContentEncryptionAlgs(jose.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			UserDefaultContentEncAlg: jose.A128GCM,
			UserContentEncAlgs:       []jose.ContentEncryption{jose.A128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCR(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var handleDCRFunc goidc.HandleDynamicClientFunc = func(
		r *http.Request,
		c *goidc.ClientMetaInfo,
	) error {
		return nil
	}
	var validateInitialTokenFunc goidc.ValidateInitialAccessTokenFunc = func(
		r *http.Request,
		s string,
	) error {
		return nil
	}

	// When.
	err := WithDCR(handleDCRFunc, validateInitialTokenFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.DCRIsEnabled {
		t.Error("DCRIsEnabled cannot be false")
	}

	if p.config.HandleDynamicClientFunc == nil {
		t.Error("HandleDynamicClientFunc cannot be nil")
	}

	if p.config.ValidateInitialAccessTokenFunc == nil {
		t.Error("ValidateInitialAccessTokenFunc cannot be nil")
	}
}

func TestWithDCRTokenRotation(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithDCRTokenRotation()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			DCRTokenRotationIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClientCredentialsGrant(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithClientCredentialsGrant()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			GrantTypes: []goidc.GrantType{goidc.GrantClientCredentials},
		},
	}
	if diff := cmp.Diff(
		p,
		want,
		cmp.AllowUnexported(Provider{}),
	); diff != "" {
		t.Error(diff)
	}
}

func TestWithRefreshTokenGrant(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var shouldIssueRefreshTokenFunc goidc.ShouldIssueRefreshTokenFunc = func(
		c *goidc.Client,
		gi goidc.GrantInfo,
	) bool {
		return false
	}

	// When.
	err := WithRefreshTokenGrant(shouldIssueRefreshTokenFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(p.config.GrantTypes, goidc.GrantRefreshToken) {
		t.Error("refresh token grant is missing")
	}

	if p.config.ShouldIssueRefreshTokenFunc == nil {
		t.Error("ValidateInitialAccessTokenFunc cannot be nil")
	}
}

func TestWithRefreshTokenLifetimeSecs(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithRefreshTokenLifetime(600)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			RefreshTokenLifetimeSecs: 600,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithRefreshTokenRotation(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithRefreshTokenRotation()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			RefreshTokenRotationIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithOpenIDScopeRequired(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithOpenIDScopeRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			OpenIDIsRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenOptions(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var tokenOpts goidc.TokenOptionsFunc = func(
		grantInfo goidc.GrantInfo,
	) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(10, 60)
	}

	// When.
	err := WithTokenOptions(tokenOpts)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.TokenOptionsFunc == nil {
		t.Error("TokenOptionsFunc cannot be nil")
	}
}

func TestWithHandleGrantFunc(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var grantHandler goidc.HandleGrantFunc = func(r *http.Request, gi *goidc.GrantInfo) error {
		return nil
	}

	// When.
	err := WithHandleGrantFunc(grantHandler)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HandleGrantFunc == nil {
		t.Error("HandleGrantFunc cannot be nil")
	}
}

func TestWithImplicitGrant(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithImplicitGrant()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			GrantTypes: []goidc.GrantType{goidc.GrantImplicit},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithScopes(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When
	err := WithScopes(goidc.ScopeEmail)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(p.config.Scopes) != 2 {
		t.Error("there should be only two scopes")
	}
}

func TestWithPAR(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithPAR()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			PARIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPARRequired(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithPARRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			PARIsEnabled:  true,
			PARIsRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUnregisteredRedirectURIsForPAR(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithUnregisteredRedirectURIsForPAR()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			PARAllowUnregisteredRedirectURI: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAR(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJAR(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JARIsEnabled: true,
			JARSigAlgs:   []jose.SignatureAlgorithm{jose.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAR_NoAlgInformed(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJAR(jose.RS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JARIsEnabled: true,
			JARSigAlgs:   []jose.SignatureAlgorithm{jose.RS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARRequired(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJARRequired(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JARIsEnabled:  true,
			JARIsRequired: true,
			JARSigAlgs:    []jose.SignatureAlgorithm{jose.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAREncryption(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJAREncryption("enc_key")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JAREncIsEnabled: true,
			JARKeyEncIDs:    []string{"enc_key"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJARContentEncryptionAlgs(jose.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JARContentEncAlgs: []jose.ContentEncryption{jose.A128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARM(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJARM("sig_key")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JARMIsEnabled:       true,
			JARMDefaultSigKeyID: "sig_key",
			JARMSigKeyIDs:       []string{"sig_key"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMEncryption(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJARMEncryption(jose.RSA_OAEP)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JARMEncIsEnabled: true,
			JARMKeyEncAlgs:   []jose.KeyAlgorithm{jose.RSA_OAEP},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMEncryption_NoAlgInformed(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJARMEncryption(jose.RSA_OAEP_256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JARMEncIsEnabled: true,
			JARMKeyEncAlgs:   []jose.KeyAlgorithm{jose.RSA_OAEP_256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJARMContentEncryptionAlgs(jose.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			JARMDefaultContentEncAlg: jose.A128GCM,
			JARMContentEncAlgs:       []jose.ContentEncryption{jose.A128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAssertionLifetime(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithAssertionLifetime(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			AssertionLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIssuerResponseParameter(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithIssuerResponseParameter()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			IssuerRespParamIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthorizationDetails(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var compareDetailsFunc goidc.CompareAuthDetailsFunc = func(
		granted, requested []goidc.AuthorizationDetail,
	) error {
		return nil
	}

	// When.
	err := WithAuthorizationDetails(compareDetailsFunc, "detail_type")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.AuthDetailsIsEnabled {
		t.Errorf("auth details must be enabled")
	}

	if p.config.CompareAuthDetailsFunc == nil {
		t.Error("CompareAuthDetailsFunc cannot be nil")
	}

	if p.config.AuthDetailTypes == nil {
		t.Error("auth detail types should be set")
	}

}

func TestWithMTLS(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var clientCertFunc goidc.ClientCertFunc = func(
		r *http.Request,
	) (*x509.Certificate, error) {
		return nil, nil
	}

	// When.
	err := WithMTLS("https://matls-example.com", clientCertFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.MTLSHost != "https://matls-example.com" {
		t.Errorf("MTLSHost = %s, want https://matls-example.com", p.config.MTLSHost)
	}

	if p.config.ClientCertFunc == nil {
		t.Error("ClientCertFunc cannot be nil")
	}
}

func TestWithTLSCertTokenBinding(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithTLSCertTokenBinding()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			MTLSTokenBindingIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTLSCertTokenBindingRequired(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithTLSCertTokenBindingRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			MTLSTokenBindingIsEnabled:  true,
			MTLSTokenBindingIsRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoP(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithDPoP(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			DPoPIsEnabled: true,
			DPoPSigAlgs:   []jose.SignatureAlgorithm{jose.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoP_NoAlgInformed(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithDPoP(jose.RS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			DPoPIsEnabled: true,
			DPoPSigAlgs:   []jose.SignatureAlgorithm{jose.RS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoPRequired(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithDPoPRequired(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			DPoPIsEnabled:  true,
			DPoPIsRequired: true,
			DPoPSigAlgs:    []jose.SignatureAlgorithm{jose.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenBindingRequired(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithTokenBindingRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			TokenBindingIsRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIntrospection(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithTokenIntrospection(
		nil,
		goidc.ClientAuthnSecretPost,
	)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			TokenIntrospectionIsEnabled:    true,
			TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnSecretPost},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenRevocation(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithTokenRevocation(nil, goidc.ClientAuthnNone)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			TokenRevocationIsEnabled:    true,
			TokenRevocationAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnNone},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPKCE(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithPKCE(goidc.CodeChallengeMethodPlain)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			PKCEIsEnabled:              true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodPlain,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPKCE_NoMethodInformed(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithPKCE(goidc.CodeChallengeMethodSHA256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			PKCEIsEnabled:              true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodSHA256,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPKCERequired(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithPKCERequired(goidc.CodeChallengeMethodPlain)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			PKCEIsEnabled:              true,
			PKCEIsRequired:             true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodPlain,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithACRs(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithACRs("0")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			ACRs: []goidc.ACR{"0"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDisplayValues(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithDisplayValues(goidc.DisplayValuePage)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			DisplayValues: []goidc.DisplayValue{goidc.DisplayValuePage},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthenticationSessionTimeout(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithAuthenticationSessionTimeout(10)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			AuthnSessionTimeoutSecs: 10,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithStaticClient(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	c, _ := oidctest.NewClient(t)

	// When.
	err := WithStaticClient(c)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			StaticClients: []*goidc.Client{c},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPolicy(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	policy := goidc.AuthnPolicy{
		ID: "policy_id",
	}

	// When.
	err := WithPolicy(policy)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			Policies: []goidc.AuthnPolicy{policy},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithRenderErrorFunc(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var renderFunc goidc.RenderErrorFunc = func(
		w http.ResponseWriter,
		r *http.Request,
		err error,
	) error {
		return nil
	}

	// When.
	err := WithRenderErrorFunc(renderFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.RenderErrorFunc == nil {
		t.Error("RenderErrorFunc cannot be nil")
	}
}

func TestWithHandleErrorFunc(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var handleErrorFunc goidc.HandleErrorFunc = func(
		r *http.Request,
		err error,
	) {
	}

	// When.
	err := WithHandleErrorFunc(handleErrorFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HandleErrorFunc == nil {
		t.Error("HandleErrorFunc cannot be nil")
	}
}

func TestWithCheckJTIFunc(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}
	var checkJTIFunc goidc.CheckJTIFunc = func(ctx context.Context, s string) error {
		return nil
	}

	// When.
	err := WithCheckJTIFunc(checkJTIFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.CheckJTIFunc == nil {
		t.Error("CheckJTIFunc cannot be nil")
	}
}

func TestWithResourceIndicators(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithResourceIndicators("https://resource.com")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			ResourceIndicatorsIsEnabled: true,
			Resources:                   []string{"https://resource.com"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithResourceIndicatorsRequired(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithResourceIndicatorsRequired("https://resource.com")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := Provider{
		config: &oidc.Configuration{
			ResourceIndicatorsIsEnabled:  true,
			ResourceIndicatorsIsRequired: true,
			Resources:                    []string{"https://resource.com"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithHTTPClientFunc(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithHTTPClientFunc(func(r *http.Request) *http.Client {
		return http.DefaultClient
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HTTPClientFunc == nil {
		t.Error("HTTPClientFunc cannot be nil")
	}
}

func TestJWTBearerGrant(t *testing.T) {
	// Given.
	p := Provider{
		config: &oidc.Configuration{},
	}

	// When.
	err := WithJWTBearerGrant(func(r *http.Request, assertion string) (goidc.JWTBearerGrantInfo, error) {
		return goidc.JWTBearerGrantInfo{}, nil
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HandleJWTBearerGrantAssertionFunc == nil {
		t.Error("HandleJWTBearerGrantAssertionFunc cannot be nil")
	}
}
