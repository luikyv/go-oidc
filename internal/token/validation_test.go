package token

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestContainsAllScopes(t *testing.T) {
	testCases := []struct {
		name      string
		available string
		requested string
		want      bool
	}{
		{
			name:      "empty requested",
			available: "scope1 scope2",
			requested: "",
			want:      true,
		},
		{
			name:      "subset",
			available: "scope1 scope2 scope3",
			requested: "scope1 scope2",
			want:      true,
		},
		{
			name:      "exact match",
			available: "scope1 scope2",
			requested: "scope1 scope2",
			want:      true,
		},
		{
			name:      "superset",
			available: "scope1",
			requested: "scope1 scope2",
			want:      false,
		},
		{
			name:      "disjoint",
			available: "scope1 scope2",
			requested: "scope3 scope4",
			want:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := containsAllScopes(tc.available, tc.requested)
			if got != tc.want {
				t.Errorf("containsAllScopes(%q, %q) = %v, want %v", tc.available, tc.requested, got, tc.want)
			}
		})
	}
}

func TestIsPKCEValid_Plain(t *testing.T) {
	// Matching verifier.
	if !isPKCEValid("my_verifier", "my_verifier", goidc.CodeChallengeMethodPlain) {
		t.Error("expected valid PKCE for matching plain verifier")
	}

	// Non-matching verifier.
	if isPKCEValid("my_verifier", "wrong_challenge", goidc.CodeChallengeMethodPlain) {
		t.Error("expected invalid PKCE for non-matching plain verifier")
	}
}

func TestIsPKCEValid_SHA256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// Pre-computed SHA256 challenge for this verifier.
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// Correct verifier.
	if !isPKCEValid(verifier, challenge, goidc.CodeChallengeMethodSHA256) {
		t.Error("expected valid PKCE for correct SHA256 verifier")
	}

	// Incorrect verifier.
	if isPKCEValid("wrong_verifier_value_here_0000000000000000000", challenge, goidc.CodeChallengeMethodSHA256) {
		t.Error("expected invalid PKCE for incorrect SHA256 verifier")
	}
}

func TestValidateBindingRequirement_NotRequired(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.TokenBindingIsRequired = false

	// When.
	err := validateBindingRequirement(ctx)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBindingRequirement_RequiredButNoBinding(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.TokenBindingIsRequired = true
	ctx.DPoPIsEnabled = false
	ctx.MTLSTokenBindingIsEnabled = false

	// When.
	err := validateBindingRequirement(ctx)

	// Then.
	if err == nil {
		t.Fatal("expected error when binding is required but no mechanism is available")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
	}
}

func TestValidatePkce_CodeVerifierTooShort(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.PKCEIsEnabled = true
	ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256

	session := &goidc.AuthnSession{}
	session.CodeChallenge = "some_challenge"
	req := request{
		codeVerifier: "short", // Less than 43 chars.
	}

	// When.
	err := validatePkce(ctx, req, nil, session)

	// Then.
	if err == nil {
		t.Fatal("expected error for code_verifier shorter than 43 characters")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidGrant {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidGrant)
	}
}

func TestValidatePkce_Disabled(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.PKCEIsEnabled = false

	// When.
	err := validatePkce(ctx, request{codeVerifier: "anything"}, nil, &goidc.AuthnSession{})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateScopes_InvalidScope(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	session := &goidc.AuthnSession{
		GrantedScopes: "openid scope1",
	}
	req := request{scopes: "openid scope_not_granted"}

	// When.
	err := validateScopes(ctx, req, session)

	// Then.
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidScope {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidScope)
	}
}

func TestValidateResources_Disabled(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.ResourceIndicatorsIsEnabled = false
	req := request{
		resources: []string{"https://resource.com"},
	}

	// When.
	err := validateResources(ctx, nil, req)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateResources_ValidResource(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.ResourceIndicatorsIsEnabled = true
	available := goidc.Resources{"https://resource.com", "https://other.com"}
	req := request{
		resources: []string{"https://resource.com"},
	}

	// When.
	err := validateResources(ctx, available, req)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateResources_InvalidResource(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.ResourceIndicatorsIsEnabled = true
	available := goidc.Resources{"https://resource.com"}
	req := request{
		resources: []string{"https://unknown.com"},
	}

	// When.
	err := validateResources(ctx, available, req)

	// Then.
	if err == nil {
		t.Fatal("expected error")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidTarget {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidTarget)
	}
}
