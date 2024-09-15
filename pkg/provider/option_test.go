package provider

import (
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestWithClientStorage(t *testing.T) {
	// Given.
	p := &provider{}
	st := storage.NewClientManager()

	// When.
	err := WithClientStorage(st)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientManager: st,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthnSessionStorage(t *testing.T) {
	// Given.
	p := &provider{}
	st := storage.NewAuthnSessionManager()

	// When.
	err := WithAuthnSessionStorage(st)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			AuthnSessionManager: st,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithGrantSessionStorage(t *testing.T) {
	// Given.
	p := &provider{}
	st := storage.NewGrantSessionManager()

	// When.
	err := WithGrantSessionStorage(st)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			GrantSessionManager: st,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPathPrefix(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPathPrefix("/auth")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			EndpointPrefix: "/auth",
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJWKSEndpoint(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJWKSEndpoint("/jwks")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			EndpointJWKS: "/jwks",
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenEndpoint(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithTokenEndpoint("/token")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			EndpointToken: "/token",
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthorizeEndpoint(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithAuthorizeEndpoint("/authorize")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			EndpointAuthorize: "/authorize",
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPAREndpoint(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPAREndpoint("/par")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			EndpointPushedAuthorization: "/par",
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCREndpoint(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithDCREndpoint("/register")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			EndpointDCR: "/register",
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEndpoint(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithUserInfoEndpoint("/userinfo")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			EndpointUserInfo: "/userinfo",
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIntrospectionEndpoint(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithIntrospectionEndpoint("/introspect")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			EndpointIntrospection: "/introspect",
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClaims(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithClaims("claim_one", "claim_two")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			Claims:     []string{"claim_one", "claim_two"},
			ClaimTypes: []goidc.ClaimType{goidc.ClaimTypeNormal},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClaimTypes(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithClaimTypes(goidc.ClaimTypeDistributed)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClaimTypes: []goidc.ClaimType{goidc.ClaimTypeDistributed},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoSignatureKeyIDs(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithUserInfoSignatureKeyIDs("sig_key")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			UserDefaultSigKeyID: "sig_key",
			UserSigKeyIDs:       []string{"sig_key"},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIDTokenLifetime(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithIDTokenLifetime(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			IDTokenLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEncryption(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithUserInfoEncryption(jose.RSA_OAEP)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			UserEncIsEnabled:         true,
			UserKeyEncAlgs:           []jose.KeyAlgorithm{jose.RSA_OAEP},
			UserDefaultContentEncAlg: jose.A128CBC_HS256,
			UserContentEncAlgs:       []jose.ContentEncryption{jose.A128CBC_HS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoEncryption_NoAlgInformed(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithUserInfoEncryption()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			UserEncIsEnabled:         true,
			UserKeyEncAlgs:           []jose.KeyAlgorithm{jose.RSA_OAEP_256},
			UserDefaultContentEncAlg: jose.A128CBC_HS256,
			UserContentEncAlgs:       []jose.ContentEncryption{jose.A128CBC_HS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUserInfoContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithUserInfoContentEncryptionAlgs(jose.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			UserDefaultContentEncAlg: jose.A128GCM,
			UserContentEncAlgs:       []jose.ContentEncryption{jose.A128GCM},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDCR(t *testing.T) {
	// Given.
	p := &provider{}
	var handleDCRFunc goidc.HandleDynamicClientFunc = func(
		r *http.Request,
		c *goidc.ClientMetaInfo,
	) error {
		return nil
	}

	// When.
	err := WithDCR(handleDCRFunc)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			DCRIsEnabled:            true,
			HandleDynamicClientFunc: handleDCRFunc,
		},
	}
	if diff := cmp.Diff(
		*p,
		want,
		cmp.AllowUnexported(provider{}),
		cmpopts.IgnoreFields(provider{}, "config.HandleDynamicClientFunc"),
	); diff != "" {
		t.Error(diff)
	}

	if p.config.HandleDynamicClientFunc == nil {
		t.Error("HandleDynamicClientFunc cannot be nil")
	}
}

func TestWithDCRTokenRotation(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithDCRTokenRotation()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			DCRTokenRotationIsEnabled: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithRefreshTokenGrant(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithRefreshTokenGrant()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			GrantTypes:               []goidc.GrantType{goidc.GrantRefreshToken},
			RefreshTokenLifetimeSecs: defaultRefreshTokenLifetimeSecs,
		},
	}
	if diff := cmp.Diff(
		*p,
		want,
		cmp.AllowUnexported(provider{}),
		cmpopts.IgnoreFields(provider{}, "config.IssueRefreshTokenFunc"),
	); diff != "" {
		t.Error(diff)
	}
}

func TestWithRefreshTokenLifetimeSecs(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithRefreshTokenLifetimeSecs(600)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			RefreshTokenLifetimeSecs: 600,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithRefreshTokenRotation(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithRefreshTokenRotation()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			RefreshTokenRotationIsEnabled: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithOpenIDScopeRequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithOpenIDScopeRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			OpenIDIsRequired: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithShouldIssueRefreshTokenFunc(t *testing.T) {
	// Given.
	p := &provider{}
	var f goidc.ShouldIssueRefreshTokenFunc = func(
		client *goidc.Client,
		grantInfo goidc.GrantInfo,
	) bool {
		return false
	}

	// When.
	err := WithShouldIssueRefreshTokenFunc(f)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.config.ShouldIssueRefreshTokenFunc == nil {
		t.Error("IssueRefreshTokenFunc cannot be nil")
	}
}

func TestWithTokenOptions(t *testing.T) {
	// Given.
	p := &provider{}
	var tokenOpts goidc.TokenOptionsFunc = func(
		client *goidc.Client,
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
	p := &provider{}
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
	p := &provider{}

	// When.
	err := WithImplicitGrant()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			GrantTypes: []goidc.GrantType{goidc.GrantImplicit},
			ResponseTypes: []goidc.ResponseType{
				goidc.ResponseTypeToken,
				goidc.ResponseTypeIDToken,
				goidc.ResponseTypeIDTokenAndToken,
				goidc.ResponseTypeCodeAndIDToken,
				goidc.ResponseTypeCodeAndToken,
				goidc.ResponseTypeCodeAndIDTokenAndToken,
			},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithScopes(t *testing.T) {
	// Given.
	p := &provider{}

	// When
	err := WithScopes(goidc.ScopeEmail)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			Scopes: []goidc.Scope{goidc.ScopeEmail, goidc.ScopeOpenID},
		},
	}
	if diff := cmp.Diff(
		*p,
		want,
		cmp.AllowUnexported(provider{}),
		cmpopts.IgnoreFields(goidc.Scope{}, "Matches"),
	); diff != "" {
		t.Error(diff)
	}
}

func TestWithPAR(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPAR()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			PARIsEnabled:    true,
			PARLifetimeSecs: defaultPARLifetimeSecs,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPARRequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPARRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			PARIsEnabled:    true,
			PARIsRequired:   true,
			PARLifetimeSecs: defaultPARLifetimeSecs,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithUnregisteredRedirectURIsForPAR(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithUnregisteredRedirectURIsForPAR()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			PARAllowUnregisteredRedirectURI: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAR(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJAR(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARIsEnabled:    true,
			JARLifetimeSecs: defaultJWTLifetimeSecs,
			JARSigAlgs:      []jose.SignatureAlgorithm{jose.PS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAR_NoAlgInformed(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJAR()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARIsEnabled:    true,
			JARLifetimeSecs: defaultJWTLifetimeSecs,
			JARSigAlgs:      []jose.SignatureAlgorithm{jose.RS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARRequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJARRequired(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARIsEnabled:    true,
			JARIsRequired:   true,
			JARLifetimeSecs: defaultJWTLifetimeSecs,
			JARSigAlgs:      []jose.SignatureAlgorithm{jose.PS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJAREncryption(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJAREncryption("enc_key")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JAREncIsEnabled:         true,
			JARKeyEncIDs:            []string{"enc_key"},
			JARDefaultContentEncAlg: jose.A128CBC_HS256,
			JARContentEncAlgs:       []jose.ContentEncryption{jose.A128CBC_HS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJARContentEncryptionAlgs(jose.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARDefaultContentEncAlg: jose.A128GCM,
			JARContentEncAlgs:       []jose.ContentEncryption{jose.A128GCM},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARM(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJARM("sig_key")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARMIsEnabled: true,
			ResponseModes: []goidc.ResponseMode{
				goidc.ResponseModeJWT,
				goidc.ResponseModeQueryJWT,
				goidc.ResponseModeFragmentJWT,
				goidc.ResponseModeFormPostJWT,
			},
			JARMLifetimeSecs:    defaultJWTLifetimeSecs,
			JARMDefaultSigKeyID: "sig_key",
			JARMSigKeyIDs:       []string{"sig_key"},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMLifetimeSecs(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJARMLifetimeSecs(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARMLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMEncryption(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJARMEncryption(jose.RSA_OAEP)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARMEncIsEnabled:         true,
			JARMKeyEncAlgs:           []jose.KeyAlgorithm{jose.RSA_OAEP},
			JARMDefaultContentEncAlg: jose.A128CBC_HS256,
			JARMContentEncAlgs:       []jose.ContentEncryption{jose.A128CBC_HS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMEncryption_NoAlgInformed(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJARMEncryption()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARMEncIsEnabled:         true,
			JARMKeyEncAlgs:           []jose.KeyAlgorithm{jose.RSA_OAEP_256},
			JARMDefaultContentEncAlg: jose.A128CBC_HS256,
			JARMContentEncAlgs:       []jose.ContentEncryption{jose.A128CBC_HS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithJARMContentEncryptionAlgs(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithJARMContentEncryptionAlgs(jose.A128GCM)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			JARMDefaultContentEncAlg: jose.A128GCM,
			JARMContentEncAlgs:       []jose.ContentEncryption{jose.A128GCM},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithBasicSecretAuthn(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithBasicSecretAuthn()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnSecretBasic},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretPostAuthn(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithSecretPostAuthn()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnSecretPost},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPrivateKeyJWTAuthn(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPrivateKeyJWTAuthn(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods:   []goidc.ClientAuthnType{goidc.ClientAuthnPrivateKeyJWT},
			PrivateKeyJWTSigAlgs: []jose.SignatureAlgorithm{jose.PS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPrivateKeyJWTAuthn_NoAlgInformed(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPrivateKeyJWTAuthn()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods:   []goidc.ClientAuthnType{goidc.ClientAuthnPrivateKeyJWT},
			PrivateKeyJWTSigAlgs: []jose.SignatureAlgorithm{jose.RS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithSecretJWTAuthn(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithSecretJWTAuthn(jose.HS384)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods:     []goidc.ClientAuthnType{goidc.ClientAuthnSecretJWT},
			ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS384},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithClientSecretJWTAuthn_NoAlgInformed(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithSecretJWTAuthn()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods:     []goidc.ClientAuthnType{goidc.ClientAuthnSecretJWT},
			ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAssertionLifetime(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithAssertionLifetime(60)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			AssertionLifetimeSecs: 60,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTLSAuthn(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithTLSAuthn()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnTLS},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithSelfSignedTLSAuthn(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithSelfSignedTLSAuthn()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnSelfSignedTLS},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithNoneAuthn(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithNoneAuthn()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ClientAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnNone},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIssuerResponseParameter(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithIssuerResponseParameter()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			IssuerRespParamIsEnabled: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthorizationDetails(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithAuthorizationDetails("detail_type")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			AuthDetailsIsEnabled: true,
			AuthDetailTypes:      []string{"detail_type"},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithMTLS(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithMTLS("https://matls-example.com")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			MTLSIsEnabled: true,
			MTLSHost:      "https://matls-example.com",
		},
	}
	if diff := cmp.Diff(
		*p,
		want,
		cmp.AllowUnexported(provider{}),
		cmpopts.IgnoreFields(provider{}, "config.ClientCertFunc"),
	); diff != "" {
		t.Error(diff)
	}

	if p.config.ClientCertFunc == nil {
		t.Error("ClientCertFunc cannot be nil")
	}
}

func TestWithTLSCertTokenBinding(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithTLSCertTokenBinding()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			MTLSTokenBindingIsEnabled: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTLSCertTokenBindingRequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithTLSCertTokenBindingRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			MTLSTokenBindingIsEnabled:  true,
			MTLSTokenBindingIsRequired: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoP(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithDPoP(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			DPoPIsEnabled:    true,
			DPoPSigAlgs:      []jose.SignatureAlgorithm{jose.PS256},
			DPoPLifetimeSecs: defaultJWTLifetimeSecs,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoP_NoAlgInformed(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithDPoP()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			DPoPIsEnabled:    true,
			DPoPSigAlgs:      []jose.SignatureAlgorithm{jose.RS256},
			DPoPLifetimeSecs: defaultJWTLifetimeSecs,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDPoPRequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithDPoPRequired(jose.PS256)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			DPoPIsEnabled:    true,
			DPoPIsRequired:   true,
			DPoPSigAlgs:      []jose.SignatureAlgorithm{jose.PS256},
			DPoPLifetimeSecs: defaultJWTLifetimeSecs,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithTokenBindingRequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithTokenBindingRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			TokenBindingIsRequired: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithIntrospection(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithIntrospection(goidc.ClientAuthnSecretPost)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			IntrospectionIsEnabled:          true,
			IntrospectionClientAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnSecretPost},
			GrantTypes:                      []goidc.GrantType{goidc.GrantIntrospection},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPKCE(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPKCE(goidc.CodeChallengeMethodPlain)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			PKCEIsEnabled:              true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodPlain,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPKCE_NoMethodInformed(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPKCE()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			PKCEIsEnabled:              true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodSHA256,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPKCERequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithPKCERequired(goidc.CodeChallengeMethodPlain)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			PKCEIsEnabled:              true,
			PKCEIsRequired:             true,
			PKCEDefaultChallengeMethod: goidc.CodeChallengeMethodPlain,
			PKCEChallengeMethods:       []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithACRs(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithACRs("0")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ACRs: []goidc.ACR{"0"},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithDisplayValues(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithDisplayValues(goidc.DisplayValuePage)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			DisplayValues: []goidc.DisplayValue{goidc.DisplayValuePage},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithAuthenticationSessionTimeout(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithAuthenticationSessionTimeout(10)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			AuthnSessionTimeoutSecs: 10,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithStaticClient(t *testing.T) {
	// Given.
	p := &provider{}
	c, _ := oidctest.NewClient(t)

	// When.
	err := WithStaticClient(c)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			StaticClients: []*goidc.Client{c},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithPolicy(t *testing.T) {
	// Given.
	p := &provider{}
	policy := goidc.AuthnPolicy{
		ID: "policy_id",
	}

	// When.
	err := WithPolicy(policy)(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			Policies: []goidc.AuthnPolicy{policy},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithRenderErrorFunc(t *testing.T) {
	// Given.
	p := &provider{}
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

func TestWithResourceIndicators(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithResourceIndicators("https://resource.com")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ResourceIndicatorsIsEnabled: true,
			Resources:                   []string{"https://resource.com"},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithResourceIndicatorsRequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithResourceIndicatorsRequired("https://resource.com")(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			ResourceIndicatorsIsEnabled:  true,
			ResourceIndicatorsIsRequired: true,
			Resources:                    []string{"https://resource.com"},
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}

func TestWithOutterAuthorizationParamsRequired(t *testing.T) {
	// Given.
	p := &provider{}

	// When.
	err := WithOutterAuthorizationParamsRequired()(p)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := provider{
		config: oidc.Configuration{
			OutterAuthParamsRequired: true,
		},
	}
	if diff := cmp.Diff(*p, want, cmp.AllowUnexported(provider{})); diff != "" {
		t.Error(diff)
	}
}
