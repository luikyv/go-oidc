package provider

import (
	"context"
	"crypto/x509"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestWithClientStorage(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	st := storage.NewClientManager(1)

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
	p := &Provider{
		config: oidc.Configuration{},
	}
	st := storage.NewAuthnSessionManager(1)

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
	p := &Provider{
		config: oidc.Configuration{},
	}
	st := storage.NewGrantSessionManager(1)

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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPathPrefix("/auth")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			EndpointPrefix: "/auth",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJWKSEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJWKSEndpoint("/jwks")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JWKSEndpoint: "/jwks",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenEndpoint("/token")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenEndpoint: "/token",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthorizeEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithAuthorizeEndpoint("/authorize")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			AuthorizationEndpoint: "/authorize",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPAREndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPAREndpoint("/par")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PAREndpoint: "/par",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCREndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDCREndpoint("/register")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DCREndpoint: "/register",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithUserInfoEndpoint("/userinfo")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			UserInfoEndpoint: "/userinfo",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIntrospectionEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenIntrospectionEndpoint("/introspect")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IntrospectionEndpoint: "/introspect",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenRevocationEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenRevocationEndpoint("/revoke")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenRevocationEndpoint: "/revoke",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClaims(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClaims("claim_one", "claim_two")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClaimTypes(goidc.ClaimTypeDistributed)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ClaimTypes: []goidc.ClaimType{goidc.ClaimTypeDistributed},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoSignatureAlgs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithUserInfoSignatureAlgs(goidc.RS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			UserInfoDefaultSigAlg: goidc.RS256,
			UserInfoSigAlgs:       []goidc.SignatureAlgorithm{goidc.RS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIDTokenSignatureAlgs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithIDTokenSignatureAlgs(goidc.RS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IDTokenDefaultSigAlg: goidc.RS256,
			IDTokenSigAlgs:       []goidc.SignatureAlgorithm{goidc.RS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIDTokenLifetime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithIDTokenLifetime(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IDTokenLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEncryption(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithUserInfoEncryption(goidc.RSA_OAEP)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			UserInfoEncIsEnabled: true,
			UserInfoKeyEncAlgs:   []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIDTokenEncryption(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithIDTokenEncryption(goidc.RSA_OAEP)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IDTokenEncIsEnabled: true,
			IDTokenKeyEncAlgs:   []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithUserInfoContentEncryptionAlgs(goidc.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			UserInfoDefaultContentEncAlg: goidc.A128GCM,
			UserInfoContentEncAlgs:       []goidc.ContentEncryptionAlgorithm{goidc.A128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIDTokenContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithIDTokenContentEncryptionAlgs(goidc.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IDTokenDefaultContentEncAlg: goidc.A128GCM,
			IDTokenContentEncAlgs:       []goidc.ContentEncryptionAlgorithm{goidc.A128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCR(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var handleDCRFunc goidc.HandleDynamicClientFunc = func(*http.Request, string, *goidc.ClientMeta) error {
		return nil
	}
	var validateInitialTokenFunc goidc.ValidateInitialAccessTokenFunc = func(*http.Request, string) error {
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDCRTokenRotation()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DCRTokenRotationIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClientIDFunc(t *testing.T) {
	// Given.
	op := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClientIDFunc(func(context.Context) string {
		return "client_id"
	})(op)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if op.config.ClientIDFunc == nil {
		t.Error("ClientIDFunc cannot be nil")
	}
}

func TestWithClientCredentialsGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClientCredentialsGrant()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}
	var shouldIssueRefreshTokenFunc goidc.ShouldIssueRefreshTokenFunc = func(
		ctx context.Context,
		c *goidc.Client,
		gi goidc.GrantInfo,
	) bool {
		return false
	}

	// When.
	err := WithRefreshTokenGrant(shouldIssueRefreshTokenFunc, 300)(p)

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

func TestWithRefreshTokenRotation(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithRefreshTokenRotation()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			RefreshTokenRotationIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithOpenIDScopeRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithOpenIDScopeRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			OpenIDIsRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenOptions(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var tokenOpts goidc.TokenOptionsFunc = func(
		_ context.Context,
		grantInfo goidc.GrantInfo,
		client *goidc.Client,
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
	p := &Provider{
		config: oidc.Configuration{},
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithImplicitGrant()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			GrantTypes: []goidc.GrantType{goidc.GrantImplicit},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithScopes(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPAR(nil, 60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PARIsEnabled:    true,
			PARLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPARRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPARRequired(nil, 60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PARIsEnabled:    true,
			PARIsRequired:   true,
			PARLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUnregisteredRedirectURIsForPAR(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPARUnregisteredRedirectURIs()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PARAllowUnregisteredRedirectURI: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAR(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJAR(goidc.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARIsEnabled: true,
			JARSigAlgs:   []goidc.SignatureAlgorithm{goidc.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAR_NoAlgInformed(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJAR(goidc.RS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARIsEnabled: true,
			JARSigAlgs:   []goidc.SignatureAlgorithm{goidc.RS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJARRequired(goidc.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARIsEnabled:  true,
			JARIsRequired: true,
			JARSigAlgs:    []goidc.SignatureAlgorithm{goidc.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAREncryption(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJAREncryption(goidc.RSA_OAEP_256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JAREncIsEnabled: true,
			JARKeyEncAlgs:   []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJARContentEncryptionAlgs(goidc.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARContentEncAlgs: []goidc.ContentEncryptionAlgorithm{goidc.A128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARM(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJARM(goidc.RS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARMIsEnabled:     true,
			JARMDefaultSigAlg: goidc.RS256,
			JARMSigAlgs:       []goidc.SignatureAlgorithm{goidc.RS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMEncryption(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJARMEncryption(goidc.RSA_OAEP)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARMEncIsEnabled: true,
			JARMKeyEncAlgs:   []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMEncryption_NoAlgInformed(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJARMEncryption(goidc.RSA_OAEP_256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARMEncIsEnabled: true,
			JARMKeyEncAlgs:   []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJARMContentEncryptionAlgs(goidc.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARMDefaultContentEncAlg: goidc.A128GCM,
			JARMContentEncAlgs:       []goidc.ContentEncryptionAlgorithm{goidc.A128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretJWTSignatureAlgs(t *testing.T) {
	testCases := []struct {
		name          string
		alg           goidc.SignatureAlgorithm
		algs          []goidc.SignatureAlgorithm
		shouldError   bool
		expectedAlgs  []goidc.SignatureAlgorithm
		errorContains string
	}{
		{
			name:         "valid single HS256 algorithm",
			alg:          goidc.HS256,
			algs:         []goidc.SignatureAlgorithm{},
			shouldError:  false,
			expectedAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
		},
		{
			name:         "valid multiple HS algorithms",
			alg:          goidc.HS256,
			algs:         []goidc.SignatureAlgorithm{goidc.HS384, goidc.HS512},
			shouldError:  false,
			expectedAlgs: []goidc.SignatureAlgorithm{goidc.HS256, goidc.HS384, goidc.HS512},
		},
		{
			name:          "invalid asymmetric algorithm RS256",
			alg:           goidc.RS256,
			algs:          []goidc.SignatureAlgorithm{},
			shouldError:   true,
			errorContains: "asymmetric algorithms are not allowed",
		},
		{
			name:          "invalid asymmetric algorithm PS256",
			alg:           goidc.PS256,
			algs:          []goidc.SignatureAlgorithm{},
			shouldError:   true,
			errorContains: "asymmetric algorithms are not allowed",
		},
		{
			name:          "invalid none algorithm",
			alg:           goidc.None,
			algs:          []goidc.SignatureAlgorithm{},
			shouldError:   true,
			errorContains: "'none' algorithm is not allowed",
		},
		{
			name:          "mix of valid and invalid algorithms",
			alg:           goidc.HS256,
			algs:          []goidc.SignatureAlgorithm{goidc.RS256},
			shouldError:   true,
			errorContains: "asymmetric algorithms are not allowed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Given.
			p := &Provider{
				config: oidc.Configuration{},
			}

			// When.
			err := WithSecretJWTSignatureAlgs(tc.alg, tc.algs...)(p)

			// Then.
			if tc.shouldError {
				if err == nil {
					t.Error("expected an error but got none")
				} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain %q, got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if diff := cmp.Diff(p.config.ClientSecretJWTSigAlgs, tc.expectedAlgs); diff != "" {
					t.Error(diff)
				}
			}
		})
	}
}

func TestWithPrivateKeyJWTSignatureAlgs(t *testing.T) {
	testCases := []struct {
		name          string
		alg           goidc.SignatureAlgorithm
		algs          []goidc.SignatureAlgorithm
		shouldError   bool
		expectedAlgs  []goidc.SignatureAlgorithm
		errorContains string
	}{
		{
			name:         "valid single RS256 algorithm",
			alg:          goidc.RS256,
			algs:         []goidc.SignatureAlgorithm{},
			shouldError:  false,
			expectedAlgs: []goidc.SignatureAlgorithm{goidc.RS256},
		},
		{
			name:         "valid multiple asymmetric algorithms",
			alg:          goidc.RS256,
			algs:         []goidc.SignatureAlgorithm{goidc.PS256, goidc.ES256},
			shouldError:  false,
			expectedAlgs: []goidc.SignatureAlgorithm{goidc.RS256, goidc.PS256, goidc.ES256},
		},
		{
			name:          "invalid symetric algorithm HS256",
			alg:           goidc.HS256,
			algs:          []goidc.SignatureAlgorithm{},
			shouldError:   true,
			errorContains: "symetric algorithms are not allowed",
		},
		{
			name:          "invalid none algorithm",
			alg:           goidc.None,
			algs:          []goidc.SignatureAlgorithm{},
			shouldError:   true,
			errorContains: "'none' algorithm is not allowed",
		},
		{
			name:          "mix of valid and invalid algorithms",
			alg:           goidc.RS256,
			algs:          []goidc.SignatureAlgorithm{goidc.HS256},
			shouldError:   true,
			errorContains: "symetric algorithms are not allowed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Given.
			p := &Provider{
				config: oidc.Configuration{},
			}

			// When.
			err := WithPrivateKeyJWTSignatureAlgs(tc.alg, tc.algs...)(p)

			// Then.
			if tc.shouldError {
				if err == nil {
					t.Error("expected an error but got none")
				} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain %q, got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if diff := cmp.Diff(p.config.PrivateKeyJWTSigAlgs, tc.expectedAlgs); diff != "" {
					t.Error(diff)
				}
			}
		})
	}
}

func TestWithAssertionLifetime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJWTLifetime(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JWTLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIssuerResponseParameter(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithIssuerResponseParameter()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			IssuerRespParamIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthorizationDetails(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
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
	p := &Provider{
		config: oidc.Configuration{},
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTLSCertTokenBinding()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			MTLSTokenBindingIsEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTLSCertTokenBindingRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTLSCertTokenBindingRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDPoP(goidc.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DPoPIsEnabled: true,
			DPoPSigAlgs:   []goidc.SignatureAlgorithm{goidc.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoP_NoAlgInformed(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDPoP(goidc.RS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DPoPIsEnabled: true,
			DPoPSigAlgs:   []goidc.SignatureAlgorithm{goidc.RS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoPRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDPoPRequired(goidc.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DPoPIsEnabled:  true,
			DPoPIsRequired: true,
			DPoPSigAlgs:    []goidc.SignatureAlgorithm{goidc.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenBindingRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenBindingRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenBindingIsRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIntrospection(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
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

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenRevocation(nil, goidc.ClientAuthnNone)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCE(goidc.CodeChallengeMethodPlain)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCE(goidc.CodeChallengeMethodSHA256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCERequired(goidc.CodeChallengeMethodPlain)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithACRs("0")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ACRs: []goidc.ACR{"0"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDisplayValues(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDisplayValues(goidc.DisplayValuePage)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DisplayValues: []goidc.DisplayValue{goidc.DisplayValuePage},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthenticationSessionTimeout(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithAuthnSessionTimeout(10)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			AuthnSessionTimeoutSecs: 10,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithStaticClient(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	c, _ := oidctest.NewClient(t)

	// When.
	err := WithStaticClient(c)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			StaticClients: []*goidc.Client{c},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPolicies(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	policy := goidc.AuthnPolicy{
		ID: "policy_id",
	}

	// When.
	err := WithPolicies(policy)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			Policies: []goidc.AuthnPolicy{policy},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithRenderErrorFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
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

func TestWithNotifyErrorFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var handleErrorFunc goidc.NotifyErrorFunc = func(
		ctx context.Context,
		err error,
	) {
	}

	// When.
	err := WithNotifyErrorFunc(handleErrorFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.NotifyErrorFunc == nil {
		t.Error("HandleErrorFunc cannot be nil")
	}
}

func TestWithCheckJTIFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithResourceIndicators("https://resource.com")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithResourceIndicatorsRequired("https://resource.com")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
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
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithHTTPClientFunc(func(ctx context.Context) *http.Client {
		return &http.Client{}
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
	p := &Provider{
		config: oidc.Configuration{},
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
