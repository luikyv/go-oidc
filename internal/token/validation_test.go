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
