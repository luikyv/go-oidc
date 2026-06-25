package provider

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/http"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

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

func TestWithProfile(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithProfile(goidc.ProfileFAPI2)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.Profile != goidc.ProfileFAPI2 {
		t.Fatalf("Profile = %s, want %s", p.config.Profile, goidc.ProfileFAPI2)
	}
}

func TestProfileValidation(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithProfile(goidc.ProfileFAPI2, WithProfileValidation())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.Profile != goidc.ProfileFAPI2 {
		t.Fatalf("Profile = %s, want %s", p.config.Profile, goidc.ProfileFAPI2)
	}

	if !p.profileValidationEnabled {
		t.Fatal("profile validation must be enabled")
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

func TestWithRPMetadataChoices(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithRPMetadataChoices()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.RPMetadataChoicesEnabled {
		t.Fatal("RP metadata choices must be enabled")
	}
}

func TestWithDCRClientHandler(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var called bool
	f := func(context.Context, string, *goidc.ClientMeta) error {
		called = true
		return nil
	}

	// When.
	err := WithDCRClientHandler(f)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.DCRHandleClientFunc == nil {
		t.Fatal("DCRHandleClientFunc must be set")
	}

	if err := p.config.DCRHandleClientFunc(context.Background(), "client", &goidc.ClientMeta{}); err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}
	if !called {
		t.Fatal("DCRHandleClientFunc was not called")
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
			TokenIntrospectionEndpoint: "/introspect",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestTokenRevocationEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenRevocation(nil, WithTokenRevocationEndpoint("/revoke"))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenRevocationEnabled:  true,
			TokenRevocationEndpoint: "/revoke",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClientSecretVerifier(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var gotStored string
	var gotPresented string
	f := func(_ context.Context, stored, presented string) error {
		gotStored = stored
		gotPresented = presented
		return nil
	}

	// When.
	err := WithClientSecretVerifier(f)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.VerifyClientSecretFunc == nil {
		t.Fatal("VerifyClientSecretFunc must be set")
	}

	if err := p.config.VerifyClientSecretFunc(context.Background(), "stored", "presented"); err != nil {
		t.Fatalf("unexpected verifier error: %v", err)
	}
	if gotStored != "stored" || gotPresented != "presented" {
		t.Fatalf("verifier inputs = (%q, %q), want (%q, %q)", gotStored, gotPresented, "stored", "presented")
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
			UserInfoEncEnabled: true,
			UserInfoKeyEncAlgs: []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
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
			IDTokenEncEnabled: true,
			IDTokenKeyEncAlgs: []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
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

	// When.
	err := WithDCR(storage.NewManager(1))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.DCREnabled {
		t.Error("DCREnabled cannot be false")
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
			DCRTokenRotationEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCRSecretRotation(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDCRSecretRotation()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DCRSecretRotationEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCRSecretLifetime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDCRSecretLifetime(300)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DCRSecretLifetimeSecs: 300,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithLocalhostRedirectURIs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithLocalhostRedirectURIs()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			LocalhostRedirectURIEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCRClientID(t *testing.T) {
	// Given.
	op := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDCRClientID(func(context.Context) string {
		return "client_id"
	})(op)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if op.config.DCRClientIDFunc == nil {
		t.Error("ClientIDFunc cannot be nil")
	}
}

func TestWithDCRRegistrationTokenFunc(t *testing.T) {
	// Given.
	op := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDCRRegistrationTokenFunc(func(context.Context) string {
		return "registration_token"
	})(op)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if op.config.DCRRegistrationTokenFunc == nil {
		t.Error("WithDCRRegistrationTokenFunc cannot be nil")
	}
}

func TestWithAuthCodeGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	manager := storage.NewManager(1)

	// When.
	err := WithAuthCodeGrant(AuthCodeGrantConfig{
		Manager:       manager,
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthManager != manager {
		t.Error("AuthManager not set")
	}

	if !slices.Contains(p.config.GrantTypes, goidc.GrantAuthorizationCode) {
		t.Error("GrantAuthorizationCode not added")
	}

	if !slices.Contains(p.config.ResponseTypes, goidc.ResponseTypeCode) {
		t.Error("ResponseTypeCode not added")
	}
}

func TestWithRefreshTokenGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	manager := storage.NewManager(1)

	// When.
	err := WithRefreshTokenGrant(manager)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(p.config.GrantTypes, goidc.GrantRefreshToken) {
		t.Error("GrantRefreshToken not added")
	}

	if p.config.RefreshTokenManager != manager {
		t.Error("RefreshTokenManager not set")
	}
}

func TestWithRefreshTokenFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	tokenFunc := func(context.Context) string { return "refresh_token" }

	// When.
	err := WithRefreshTokenFunc(tokenFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.RefreshTokenFunc == nil {
		t.Error("WithRefreshTokenFunc cannot be nil")
	}
}

func TestWithDeviceCodeFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	codeFunc := func(context.Context) string { return "device_code" }

	// When.
	err := WithDeviceCodeFunc(codeFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.DeviceCodeFunc == nil {
		t.Error("WithDeviceCodeFunc cannot be nil")
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
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithCIBAGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	manager := storage.NewManager(1)

	// When.
	err := WithCIBAGrant(CIBAGrantConfig{
		Manager:       manager,
		DeliveryModes: []goidc.CIBATokenDeliveryMode{goidc.CIBADeliveryModePoll, goidc.CIBADeliveryModePush},
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(p.config.GrantTypes, goidc.GrantCIBA) {
		t.Error("GrantCIBA not added")
	}

	if p.config.CIBAManager != manager {
		t.Error("CIBAManager not set")
	}

	wantModes := []goidc.CIBATokenDeliveryMode{
		goidc.CIBADeliveryModePoll,
		goidc.CIBADeliveryModePush,
	}
	if diff := cmp.Diff(p.config.CIBATokenDeliveryModes, wantModes); diff != "" {
		t.Error(diff)
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
			RefreshTokenRotationEnabled: true,
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
			OpenIDRequired: true,
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
		_ *goidc.Grant,
		_ *goidc.Client,
	) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(60)
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

func TestWithGrantHandler(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var grantHandler goidc.HandleGrantFunc = func(context.Context, goidc.GrantType, *goidc.Grant) error {
		return nil
	}

	// When.
	err := WithGrantHandler(grantHandler)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HandleGrantFunc == nil {
		t.Error("HandleGrantFunc cannot be nil")
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
	manager := storage.NewManager(100)
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPAR(manager)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.PAREnabled {
		t.Error("PAREnabled should be true")
	}
	if p.config.PARManager != manager {
		t.Error("PARManager should match the configured manager")
	}
}

func TestWithPARRequired(t *testing.T) {
	// Given.
	manager := storage.NewManager(100)
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPAR(manager, WithPARRequired())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.PAREnabled {
		t.Error("PAREnabled should be true")
	}

	if !p.config.PARRequired {
		t.Error("PARRequired should be true")
	}
	if p.config.PARManager != manager {
		t.Error("PARManager should match the configured manager")
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
			PARUnregisteredRedirectURIEnabled: true,
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
	err := WithJAR([]goidc.SignatureAlgorithm{goidc.PS256})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JAREnabled: true,
			JARSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestJARRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJAR([]goidc.SignatureAlgorithm{goidc.PS256}, WithJARRequired())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JAREnabled:  true,
			JARRequired: true,
			JARSigAlgs:  []goidc.SignatureAlgorithm{goidc.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestJAREncryption(t *testing.T) {
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
			JAREncEnabled: true,
			JARKeyEncAlgs: []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestJARContentEncryptionAlgs(t *testing.T) {
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
	err := WithJARM([]goidc.SignatureAlgorithm{goidc.RS256})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARMEnabled:       true,
			JARMSigAlgDefault: goidc.RS256,
			JARMSigAlgs:       []goidc.SignatureAlgorithm{goidc.RS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestJARMEncryption(t *testing.T) {
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
			JARMEncEnabled: true,
			JARMKeyEncAlgs: []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestJARMContentEncryptionAlgs(t *testing.T) {
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
			JARMContentEncAlgDefault: goidc.A128GCM,
			JARMContentEncAlgs:       []goidc.ContentEncryptionAlgorithm{goidc.A128GCM},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
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
			IssuerRespParamEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithFormPostResponseMode(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithFormPostResponseMode()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ResponseModes: []goidc.ResponseMode{goidc.ResponseModeFormPost},
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

	// When.
	err := WithRAR([]goidc.AuthDetailType{"detail_type"})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.RAREnabled {
		t.Errorf("auth details must be enabled")
	}

	if p.config.RARDetailTypes == nil {
		t.Error("auth detail types should be set")
	}

}

func TestWithMTLS(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var clientCertFunc goidc.ClientCertFunc = func(_ context.Context) (*x509.Certificate, error) {
		return nil, nil
	}

	// When.
	err := WithMTLS(MTLSConfig{
		Host:           "https://matls-example.com",
		ClientCertFunc: clientCertFunc,
	})(p)

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
	err := WithMTLSTokenBinding()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			MTLSTokenBindingEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestOpenIDFedClientHandler(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var called bool
	f := func(context.Context, *goidc.Client) error {
		called = true
		return nil
	}

	// When.
	err := WithOpenIDFedClientHandler(f)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.OpenIDFedHandleClientFunc == nil {
		t.Fatal("OpenIDFedHandleClientFunc must be set")
	}

	if err := p.config.OpenIDFedHandleClientFunc(context.Background(), &goidc.Client{}); err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}
	if !called {
		t.Fatal("OpenIDFedHandleClientFunc was not called")
	}
}

func TestWithTLSCertTokenBindingRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithMTLSTokenBindingRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			MTLSTokenBindingEnabled:  true,
			MTLSTokenBindingRequired: true,
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
	err := WithDPoP([]goidc.SignatureAlgorithm{goidc.PS256})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DPoPEnabled: true,
			DPoPSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
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
	err := WithDPoP([]goidc.SignatureAlgorithm{goidc.PS256}, WithDPoPRequired())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			DPoPEnabled:  true,
			DPoPRequired: true,
			DPoPSigAlgs:  []goidc.SignatureAlgorithm{goidc.PS256},
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
			TokenBindingRequired: true,
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
	err := WithTokenIntrospection(nil)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenIntrospectionEnabled: true,
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
	var isAllowed goidc.IsClientAllowedFunc = func(context.Context, *goidc.Client) bool {
		return true
	}

	// When.
	err := WithTokenRevocation(isAllowed)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.TokenRevocationEnabled {
		t.Error("TokenRevocationEnabled should be true")
	}

	if p.config.TokenRevocationIsClientAllowedFunc == nil {
		t.Error("TokenRevocationIsClientAllowedFunc not set")
	}
}

func TestTokenRevocationRevokeGrantOnAccessToken(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenRevocation(nil, WithTokenRevocationRevokeGrantOnAccessToken())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.TokenRevocationEnabled {
		t.Error("TokenRevocationEnabled should be true")
	}

	if !p.config.TokenRevocationRevokeGrantOnAccessTokenEnabled {
		t.Error("TokenRevocationRevokeGrantOnAccessTokenEnabled should be true")
	}
}

func TestWithPKCE(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PKCEEnabled:                true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodPlain,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPKCE_MultipleMethods(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256, goidc.CodeChallengeMethodPlain})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PKCEEnabled:                true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodSHA256,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256, goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestPKCERequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain}, WithPKCERequired())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			PKCEEnabled:                true,
			PKCERequired:               true,
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
	err := WithAuthSessionLifetime(10)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			AuthTimeoutSecs: 10,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithStaticClients(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	c1, _ := oidctest.NewClient(t)
	c2, _ := oidctest.NewClient(t)

	// When.
	err := WithStaticClients(c1, c2)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			StaticClients: []*goidc.Client{c1, c2},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{}), cmpopts.IgnoreUnexported(goidc.Client{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthPolicies(t *testing.T) {
	p := &Provider{}
	policy := goidc.AuthnPolicy{
		ID: "policy_id",
	}

	err := WithAuthPolicies(policy)(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(p.config.AuthPolicies, []goidc.AuthnPolicy{policy}); diff != "" {
		t.Error(diff)
	}
}

func TestWithDevicePolicies(t *testing.T) {
	p := &Provider{}
	policy := goidc.AuthnPolicy{
		ID: "policy_id",
	}

	err := WithDevicePolicies(policy)(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(p.config.DevicePolicies, []goidc.AuthnPolicy{policy}); diff != "" {
		t.Error(diff)
	}
}

func TestWithErrorRenderer(t *testing.T) {
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
	err := WithErrorRenderer(renderFunc)(p)

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
	var handleErrorFunc goidc.HandleErrorFunc = func(
		ctx context.Context,
		err error,
	) {
	}

	// When.
	err := WithErrorHandler(handleErrorFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.HandleErrorFunc == nil {
		t.Error("HandleErrorFunc cannot be nil")
	}
}

func TestWithJTIConsumer(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	var consumeJTIFunc goidc.ConsumeJTIFunc = func(ctx context.Context, s string) error {
		return nil
	}

	// When.
	err := WithJTIConsumer(consumeJTIFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.ConsumeJTIFunc == nil {
		t.Error("ConsumeJTIFunc cannot be nil")
	}
}

func TestWithResourceIndicators(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithResourceIndicators([]string{"https://resource.com"})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ResourceIndicatorsEnabled: true,
			ResourceIndicators:        []string{"https://resource.com"},
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
	err := WithResourceIndicators([]string{"https://resource.com"}, WithResourceIndicatorsRequired())(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ResourceIndicatorsEnabled:  true,
			ResourceIndicatorsRequired: true,
			ResourceIndicators:         []string{"https://resource.com"},
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

func TestWithCIBAHTTPClientFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithCIBAHTTPClientFunc(func(context.Context) *http.Client {
		return &http.Client{}
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.CIBAHTTPClientFunc == nil {
		t.Error("WithCIBAHTTPClientFunc cannot be nil")
	}
}

func TestWithJWTBearerGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJWTBearerGrant(func(_ context.Context, assertion string) (goidc.JWTBearerResult, error) {
		return goidc.JWTBearerResult{}, nil
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(p.config.GrantTypes, goidc.GrantJWTBearer) {
		t.Error("GrantJWTBearer should be in GrantTypes")
	}

	if p.config.JWTBearerHandleAssertionFunc == nil {
		t.Error("JWTBearerHandleAssertionFunc cannot be nil")
	}
}

func TestWithTokenExchangeGrant(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenExchangeGrant(func(_ context.Context, _ goidc.TokenExchangeRequest) (goidc.TokenExchangeResult, error) {
		return goidc.TokenExchangeResult{}, nil
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(p.config.GrantTypes, goidc.GrantTokenExchange) {
		t.Error("GrantTokenExchange should be in GrantTypes")
	}

	if p.config.TokenExchangeHandleFunc == nil {
		t.Error("TokenExchangeHandleFunc cannot be nil")
	}
}

func TestWithTokenExchangeClientAuthnRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithTokenExchangeClientAuthnRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			TokenExchangeClientAuthnRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithGrantID(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "session_id" }

	// When.
	err := WithGrantIDFunc(idFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.GrantIDFunc == nil {
		t.Error("GrantIDFunc cannot be nil")
	}
}

func TestWithPARID(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "par_id" }

	// When.
	err := WithPARIDFunc(idFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.PARIDFunc == nil {
		t.Error("WithPARIDFunc cannot be nil")
	}
}

func TestWithCIBAID(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "auth_req_id" }

	// When.
	err := WithCIBAIDFunc(idFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.CIBAIDFunc == nil {
		t.Error("WithCIBAIDFunc cannot be nil")
	}
}

func TestOpaqueTokenFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	tokenFunc := func(context.Context, *goidc.Grant) string { return "opaque_token" }

	// When.
	err := WithTokenOptions(nil, WithOpaqueTokenFunc(tokenFunc))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.OpaqueTokenFunc == nil {
		t.Error("WithOpaqueTokenFunc cannot be nil")
	}
}

func TestWithCIBAEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithCIBAEndpoint("/ciba")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			CIBAEndpoint: "/ciba",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithCIBAJAR(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithCIBAJAR([]goidc.SignatureAlgorithm{goidc.PS256})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			CIBAJAREnabled: true,
			CIBAJARSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithCIBAJARRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithCIBAJARRequired([]goidc.SignatureAlgorithm{goidc.PS256})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			CIBAJAREnabled:  true,
			CIBAJARRequired: true,
			CIBAJARSigAlgs:  []goidc.SignatureAlgorithm{goidc.PS256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithCIBAUserCode(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithCIBAUserCode()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			CIBAUserCodeEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithCIBAPollingInterval(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithCIBAPollingInterval(5)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			CIBAPollingIntervalSecs: 5,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithCIBALifetime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithCIBALifetime(300)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			CIBADefaultSessionLifetimeSecs: 300,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestJARByReference(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJARByReference(nil)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JARByReferenceEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJWTLeewayTime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJWTLeewayTime(30)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JWTLeewayTimeSecs: 30,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClaimsParameter(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithClaimsParameter()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ClaimsParamEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJWTBearerGrantClientAuthnRequired(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJWTBearerClientAuthnRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			JWTBearerClientAuthnRequired: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithSubjectIdentifiers(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	pairwiseFunc := func(ctx context.Context, sub string, c *goidc.Client) string {
		return "pairwise_sub"
	}

	// When.
	err := WithSubjectIdentifiers(
		[]goidc.SubIdentifierType{goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise},
		WithPairwiseSubjectFunc(pairwiseFunc),
	)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.SubIdentifierTypeDefault != goidc.SubIdentifierPublic {
		t.Errorf("SubIdentifierTypeDefault = %q, want %q", p.config.SubIdentifierTypeDefault, goidc.SubIdentifierPublic)
	}
	if diff := cmp.Diff(p.config.SubIdentifierTypes, []goidc.SubIdentifierType{goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise}); diff != "" {
		t.Error(diff)
	}
	if p.config.PairwiseSubjectFunc == nil {
		t.Error("PairwiseSubjectFunc cannot be nil")
	}
}

func TestWithSigner(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	signerFunc := func(ctx context.Context, alg goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		return "kid", nil, nil
	}

	// When.
	err := WithSigner(signerFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.SignerFunc == nil {
		t.Error("SignerFunc cannot be nil")
	}
}

func TestWithDecrypter(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	decrypterFunc := func(ctx context.Context, kid string, alg goidc.KeyEncryptionAlgorithm) (crypto.Decrypter, error) {
		return nil, nil
	}

	// When.
	err := WithDecrypter(decrypterFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.DecrypterFunc == nil {
		t.Error("DecrypterFunc cannot be nil")
	}
}

func TestWithErrorURI(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithErrorURI("https://example.com/errors")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			ErrorURI: "https://example.com/errors",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthnSessionIDFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "authn_session_id" }

	// When.
	err := WithAuthnSessionIDFunc(idFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthSessionIDFunc == nil {
		t.Error("AuthnSessionGenerateIDFunc cannot be nil")
	}
}

func TestWithJWTID(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "jwt_id" }

	// When.
	err := WithJWTIDFunc(idFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.JWTIDFunc == nil {
		t.Error("JWTIDFunc cannot be nil")
	}
}

func TestAuthCodeFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	codeFunc := func(context.Context) string { return "auth_code" }

	// When.
	err := WithAuthCodeGrant(AuthCodeGrantConfig{
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
	}, WithAuthCodeFunc(codeFunc))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthCodeFunc == nil {
		t.Error("WithAuthCodeFunc cannot be nil")
	}
}

func TestAuthCodeLifetime(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithAuthCodeGrant(AuthCodeGrantConfig{
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
	}, WithAuthCodeLifetime(90))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.AuthCodeLifetimeSecs != 90 {
		t.Fatalf("AuthCodeLifetimeSecs = %d, want %d", p.config.AuthCodeLifetimeSecs, 90)
	}
}

func TestWithLogout(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	manager := storage.NewManager(10)
	handleFunc := func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) error {
		return nil
	}

	// When.
	err := WithLogout(LogoutConfig{
		Manager:    manager,
		HandleFunc: handleFunc,
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.LogoutEnabled {
		t.Error("LogoutEnabled should be true")
	}

	if p.config.LogoutManager != manager {
		t.Error("invalid logout session manager")
	}

	if p.config.HandleDefaultPostLogoutFunc == nil {
		t.Error("HandleDefaultPostLogoutFunc cannot be nil")
	}
}

func TestLogoutPolicies(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	policy := goidc.NewLogoutPolicy(
		"policy",
		func(_ *http.Request, _ *goidc.LogoutSession) bool {
			return true
		},
		func(_ http.ResponseWriter, _ *http.Request, _ *goidc.LogoutSession) (goidc.Status, error) {
			return goidc.StatusSuccess, nil
		},
	)

	// When.
	err := WithLogout(LogoutConfig{}, WithLogoutPolicies(policy))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(p.config.LogoutPolicies) != 1 {
		t.Fatalf("got %d logout policies, want 1", len(p.config.LogoutPolicies))
	}

	if p.config.LogoutPolicies[0].ID != policy.ID {
		t.Fatalf("got logout policy %q, want %q", p.config.LogoutPolicies[0].ID, policy.ID)
	}
}

func TestLogoutSessionTimeoutSecs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithLogout(LogoutConfig{}, WithLogoutSessionTimeoutSecs(600))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.LogoutEnabled {
		t.Error("LogoutEnabled should be true")
	}

	if p.config.LogoutSessionTimeoutSecs != 600 {
		t.Errorf("WithLogoutSessionTimeoutSecs = %d, want 600", p.config.LogoutSessionTimeoutSecs)
	}
}

func TestLogoutEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithLogout(LogoutConfig{}, WithLogoutEndpoint("/logout"))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.LogoutEnabled {
		t.Error("LogoutEnabled should be true")
	}

	if p.config.LogoutEndpoint != "/logout" {
		t.Errorf("WithLogoutEndpoint = %q, want %q", p.config.LogoutEndpoint, "/logout")
	}
}

func TestLogoutSessionIDFunc(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	idFunc := func(context.Context) string { return "logout_session_id" }

	// When.
	err := WithLogout(LogoutConfig{}, WithLogoutSessionIDFunc(idFunc))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.LogoutEnabled {
		t.Error("LogoutEnabled should be true")
	}

	if p.config.LogoutSessionIDFunc == nil {
		t.Error("WithLogoutSessionIDFunc cannot be nil")
	}
}

func TestWithSSF(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	jwksFunc := func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}
	receiverFunc := func(ctx context.Context) (goidc.SSFReceiver, error) {
		return goidc.SSFReceiver{ID: "receiver"}, nil
	}
	eventTypes := []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked}

	// When.
	err := WithSSF(SSFConfig{
		JWKSFunc:     jwksFunc,
		SigAlg:       goidc.RS256,
		ReceiverFunc: receiverFunc,
		EventTypes:   eventTypes,
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.SSFEnabled {
		t.Error("SSFEnabled should be true")
	}

	if p.config.SSFJWKSFunc == nil {
		t.Error("SSFJWKSFunc cannot be nil")
	}

	if p.config.SSFDefaultSigAlg != goidc.RS256 {
		t.Errorf("SSFDefaultSigAlg = %s, want %s", p.config.SSFDefaultSigAlg, goidc.RS256)
	}

	if p.config.SSFAuthenticatedReceiverFunc == nil {
		t.Error("SSFAuthenticatedReceiverFunc cannot be nil")
	}

	if diff := cmp.Diff(
		p.config.SSFEventTypes,
		[]goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
	); diff != "" {
		t.Errorf("SSFEventTypes mismatch: %s", diff)
	}
}

func TestSSFPollDelivery(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFPollDelivery(nil)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(
		p.config.SSFDeliveryMethods,
		[]goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll},
	); diff != "" {
		t.Errorf("SSFDeliveryMethods mismatch: %s", diff)
	}
}

func TestSSFPushDelivery(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	clientFunc := func(ctx context.Context) *http.Client {
		return &http.Client{}
	}

	// When.
	err := WithSSFPushDelivery(clientFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(
		p.config.SSFDeliveryMethods,
		[]goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush},
	); diff != "" {
		t.Errorf("SSFDeliveryMethods mismatch: %s", diff)
	}

	if p.config.SSFHTTPClientFunc == nil {
		t.Error("SSFHTTPClientFunc cannot be nil")
	}
}

func TestSSFEventStreamStatusManagement(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFEventStreamStatusManagement()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFIsStatusManagementEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFStatusEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFStatusEndpoint("/ssf/status")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFStatusEndpoint: "/ssf/status",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFEventStreamSubjectManagement(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFEventStreamSubjectManagement()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFIsSubjectManagementEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFAddSubjectEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFAddSubjectEndpoint("/ssf/subjects/add")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFAddSubjectEndpoint: "/ssf/subjects/add",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFRemoveSubjectEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFRemoveSubjectEndpoint("/ssf/subjects/remove")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFRemoveSubjectEndpoint: "/ssf/subjects/remove",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFEventStreamVerification(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFEventStreamVerification(nil)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFIsVerificationEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFMinVerificationInterval(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFMinVerificationInterval(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFMinVerificationInterval: 60,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFDefaultSubjects(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFDefaultSubjects(goidc.SSFDefaultSubjectAll)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFDefaultSubjects: goidc.SSFDefaultSubjectAll,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFCriticalSubjectMembers(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFCriticalSubjectMembers("user", "tenant")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFCriticalSubjectMembers: []string{"user", "tenant"},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFAuthorizationSchemes(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	scheme := goidc.SSFAuthorizationScheme{SpecificationURN: "bearer"}

	// When.
	err := WithSSFAuthorizationSchemes(scheme)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFAuthorizationSchemes: []goidc.SSFAuthorizationScheme{scheme},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestSSFInactivityTimeout(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	handleFunc := func(ctx context.Context, stream *goidc.SSFEventStream) error {
		return nil
	}

	// When.
	err := WithSSFInactivityTimeout(3600, handleFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.SSFInactivityTimeoutSecs != 3600 {
		t.Errorf("got %d, want 3600", p.config.SSFInactivityTimeoutSecs)
	}

	if p.config.SSFHandleExpiredEventStreamFunc == nil {
		t.Error("SSFHandleExpiredEventStreamFunc cannot be nil")
	}
}

func TestSSFMultipleStreamsPerReceiver(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithSSFMultipleStreamsPerReceiver()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			SSFMultipleStreamsPerReceiverEnabled: true,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithNoneAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithNoneAuthn()(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []goidc.AuthnMethod{goidc.AuthnMethodNone}
	if diff := cmp.Diff(p.config.AuthnMethods, want); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretPostAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithSecretPostAuthn()(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []goidc.AuthnMethod{goidc.AuthnMethodSecretPost}
	if diff := cmp.Diff(p.config.AuthnMethods, want); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretBasicAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithSecretBasicAuthn()(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []goidc.AuthnMethod{goidc.AuthnMethodSecretBasic}
	if diff := cmp.Diff(p.config.AuthnMethods, want); diff != "" {
		t.Error(diff)
	}
}

func TestWithPrivateKeyJWTAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithPrivateKeyJWTAuthn(goidc.RS256, goidc.PS256)(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantMethods := []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT}
	if diff := cmp.Diff(p.config.AuthnMethods, wantMethods); diff != "" {
		t.Error(diff)
	}
	wantAlgs := []goidc.SignatureAlgorithm{goidc.RS256, goidc.PS256}
	if diff := cmp.Diff(p.config.AuthnMethodPrivateKeyJWTSigAlgs, wantAlgs); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretJWTAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithSecretJWTAuthn(goidc.HS256)(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantMethods := []goidc.AuthnMethod{goidc.AuthnMethodSecretJWT}
	if diff := cmp.Diff(p.config.AuthnMethods, wantMethods); diff != "" {
		t.Error(diff)
	}
	wantAlgs := []goidc.SignatureAlgorithm{goidc.HS256}
	if diff := cmp.Diff(p.config.AuthnMethodSecretJWTSigAlgs, wantAlgs); diff != "" {
		t.Error(diff)
	}
}

func TestWithTLSAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithTLSAuthn()(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []goidc.AuthnMethod{goidc.AuthnMethodTLS}
	if diff := cmp.Diff(p.config.AuthnMethods, want); diff != "" {
		t.Error(diff)
	}
}

func TestWithSelfSignedTLSAuthn(t *testing.T) {
	p := &Provider{}
	if err := WithSelfSignedTLSAuthn()(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []goidc.AuthnMethod{goidc.AuthnMethodSelfSignedTLS}
	if diff := cmp.Diff(p.config.AuthnMethods, want); diff != "" {
		t.Error(diff)
	}
}

func TestWithAttestationJWTAuthn(t *testing.T) {
	p := &Provider{}
	issuer := goidc.AttestationIssuer{Issuer: "https://attester.example.com", JWKSURI: "https://attester.example.com/jwks"}
	if err := WithAttestationJWTAuthn(issuer)(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantMethods := []goidc.AuthnMethod{goidc.AuthnMethodAttestationJWT}
	if diff := cmp.Diff(p.config.AuthnMethods, wantMethods); diff != "" {
		t.Error(diff)
	}
	wantIssuers := []goidc.AttestationIssuer{issuer}
	if diff := cmp.Diff(p.config.AuthnMethodAttestationJWTIssuers, wantIssuers); diff != "" {
		t.Error(diff)
	}
}

func TestWithCIBASessionHandler(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	f := func(ctx context.Context, as *goidc.AuthnSession, c *goidc.Client) error {
		return nil
	}

	// When.
	err := WithCIBASessionHandler(f)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.CIBAHandleSessionFunc == nil {
		t.Error("CIBAHandleSessionFunc cannot be nil")
	}
}

func TestWithOpenIDFed(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	jwksFunc := func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, nil
	}

	// When.
	err := WithOpenIDFederation(OpenIDFedConfig{
		Manager:        storage.NewManager(1),
		JWKSFunc:       jwksFunc,
		SigAlg:         goidc.RS256,
		AuthorityHints: []string{"https://authority.hint"},
		TrustedAnchors: []string{"https://trust.anchor"},
	})(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.OpenIDFedEnabled {
		t.Error("OpenIDFedEnabled should be true")
	}

	if p.config.OpenIDFedJWKSFunc == nil {
		t.Error("OpenIDFedJWKSFunc cannot be nil")
	}

	if len(p.config.OpenIDFedAuthorityHints) != 1 || p.config.OpenIDFedAuthorityHints[0] != "https://authority.hint" {
		t.Error("OpenIDFedAuthorityHints not set correctly")
	}

	if len(p.config.OpenIDFedTrustedAnchors) != 1 || p.config.OpenIDFedTrustedAnchors[0] != "https://trust.anchor" {
		t.Error("OpenIDFedTrustedAuthorities not set correctly")
	}

	if p.config.OpenIDFedSigAlg != goidc.RS256 {
		t.Errorf("OpenIDFedSigAlg = %s, want %s", p.config.OpenIDFedSigAlg, goidc.RS256)
	}
}

func TestOpenIDFedSignatureAlgs(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithOpenIDFedSignatureAlgs(goidc.RS256, goidc.ES256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			OpenIDFedSigAlgs: []goidc.SignatureAlgorithm{goidc.RS256, goidc.ES256},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestOpenIDFedSigner(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	signerFunc := func(ctx context.Context, alg goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		return "kid", nil, nil
	}

	// When.
	err := WithOpenIDFedSigner(signerFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.OpenIDFedSignerFunc == nil {
		t.Error("OpenIDFedSignerFunc cannot be nil")
	}
}

func TestOpenIDFedRequiredClientTrustMarks(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	trustMarksFunc := func(ctx context.Context, client *goidc.Client) []goidc.TrustMark {
		return []goidc.TrustMark{"https://trust.mark"}
	}

	// When.
	err := WithOpenIDFedRequiredClientTrustMarks(trustMarksFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.OpenIDFedRequiredClientTrustMarksFunc == nil {
		t.Error("OpenIDFedRequiredTrustMarksFunc cannot be nil")
	}
}

func TestOpenIDFedClientRegistrationTypes(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithOpenIDFedClientRegistrationTypes(goidc.ClientRegistrationTypeAutomatic)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			OpenIDFedClientRegTypes: []goidc.ClientRegistrationType{goidc.ClientRegistrationTypeAutomatic},
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestOpenIDFedRegistrationEndpoint(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithOpenIDFedRegistrationEndpoint("/federation/register")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			OpenIDFedRegistrationEndpoint: "/federation/register",
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestOpenIDFedTrustChainMaxDepth(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithOpenIDFedTrustChainMaxDepth(5)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Provider{
		config: oidc.Configuration{
			OpenIDFedTrustChainMaxDepth: 5,
		},
	}
	if diff := cmp.Diff(p, want, cmp.AllowUnexported(Provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestOpenIDFedTrustMarks(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	marks := []goidc.TrustMarkConfig{
		{Mark: "https://example.com/trust-mark", Issuer: "https://issuer.example.com"},
	}

	// When.
	err := WithOpenIDFedTrustMarks(marks...)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(p.config.OpenIDFedTrustMarkConfigs, marks); diff != "" {
		t.Error(diff)
	}
}

func TestWithCredentialIssuers(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}
	issuers := []goidc.VCIssuer{
		{Issuer: "issuer-1"},
		{Issuer: "issuer-2"},
	}

	// When.
	err := WithVCI(WithVCIExternal(issuers))(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !p.config.VCIEnabled {
		t.Fatal("VC must be enabled")
	}
	if diff := cmp.Diff(p.config.VCIIssuers, issuers); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARM_NoneAlgorithm(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithJARM([]goidc.SignatureAlgorithm{goidc.None})(p)

	// Then.
	if err == nil {
		t.Error("expected error for 'none' algorithm")
	}
}

func TestWithDPoP_NoneAlgorithm(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithDPoP([]goidc.SignatureAlgorithm{goidc.None})(p)

	// Then.
	if err == nil {
		t.Error("expected error for 'none' algorithm")
	}
}

func TestWithScopes_OpenIDScopeAlreadyPresent(t *testing.T) {
	// Given.
	p := &Provider{
		config: oidc.Configuration{},
	}

	// When.
	err := WithScopes(goidc.ScopeOpenID, goidc.ScopeEmail)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// OpenID scope should not be duplicated.
	openIDCount := 0
	for _, s := range p.config.Scopes {
		if s.ID == goidc.ScopeOpenID.ID {
			openIDCount++
		}
	}
	if openIDCount != 1 {
		t.Errorf("expected 1 openid scope, got %d", openIDCount)
	}
}
