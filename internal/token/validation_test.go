package token

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidatePKCE_Plain_Valid(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.PKCEIsEnabled = true
	ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodPlain
	ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain}

	verifier := "0123456789abcdef0123456789abcdef0123456789a"
	session := &goidc.AuthnSession{}
	session.CodeChallenge = verifier
	session.CodeChallengeMethod = goidc.CodeChallengeMethodPlain
	req := request{codeVerifier: verifier}

	// When.
	err := validatePKCE(ctx, req, nil, session)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePKCE_Plain_Invalid(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.PKCEIsEnabled = true
	ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodPlain
	ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain}

	session := &goidc.AuthnSession{}
	session.CodeChallenge = "0123456789abcdef0123456789abcdef0123456789a"
	session.CodeChallengeMethod = goidc.CodeChallengeMethodPlain
	req := request{codeVerifier: "0123456789abcdef0123456789abcdef0123456789b"}

	// When.
	err := validatePKCE(ctx, req, nil, session)

	// Then.
	if err == nil {
		t.Fatal("expected error for mismatched plain verifier")
	}
}

func TestValidatePKCE_SHA256_Valid(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.PKCEIsEnabled = true
	ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
	ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	session := &goidc.AuthnSession{}
	session.CodeChallenge = challenge
	session.CodeChallengeMethod = goidc.CodeChallengeMethodSHA256
	req := request{codeVerifier: verifier}

	// When.
	err := validatePKCE(ctx, req, nil, session)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePKCE_SHA256_Invalid(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.PKCEIsEnabled = true
	ctx.PKCEDefaultChallengeMethod = goidc.CodeChallengeMethodSHA256
	ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}

	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	session := &goidc.AuthnSession{}
	session.CodeChallenge = challenge
	session.CodeChallengeMethod = goidc.CodeChallengeMethodSHA256
	req := request{codeVerifier: "wrong_verifier_value_here_0000000000000000000"}

	// When.
	err := validatePKCE(ctx, req, nil, session)

	// Then.
	if err == nil {
		t.Fatal("expected error for incorrect SHA256 verifier")
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
	err := validatePKCE(ctx, req, nil, session)

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
	err := validatePKCE(ctx, request{codeVerifier: "anything"}, nil, &goidc.AuthnSession{})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateScopes_InvalidScope(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	c, _ := oidctest.NewClient(t)
	req := request{scopes: "openid scope_not_granted"}

	// When.
	err := validateScopes(ctx, req, c, "openid scope1")

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
	err := validateResources(ctx, req, nil)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateResources_ValidResource(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.ResourceIndicatorsIsEnabled = true
	ctx.Resources = []string{"https://resource.com", "https://other.com"}
	granted := goidc.Resources{"https://resource.com", "https://other.com"}
	req := request{
		resources: []string{"https://resource.com"},
	}

	// When.
	err := validateResources(ctx, req, granted)

	// Then.
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateResources_InvalidResource(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.ResourceIndicatorsIsEnabled = true
	granted := goidc.Resources{"https://resource.com"}
	req := request{
		resources: []string{"https://unknown.com"},
	}

	// When.
	err := validateResources(ctx, req, granted)

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
