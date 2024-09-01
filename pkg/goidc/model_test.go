package goidc_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestWithClaims(t *testing.T) {
	// Given.
	tokenOptions := goidc.TokenOptions{}

	for i := 0; i < 2; i++ {
		// When.
		tokenOptions = tokenOptions.WithClaims(map[string]any{
			"claim": "value",
		})
		// Then.
		if tokenOptions.AdditionalClaims["claim"] != "value" {
			t.Errorf("AdditionalClaims[\"claim\"] = %v, want value",
				tokenOptions.AdditionalClaims["claim"])
		}
	}
}

func TestAuthorizationDetails(t *testing.T) {
	// Given.
	authDetails := goidc.AuthorizationDetail{
		"type":       "random_type",
		"identifier": "random_identifier",
		"actions":    []string{"random_action"},
	}

	// Then.
	if authDetails.Type() != "random_type" {
		t.Errorf("Type() = %v, want random_type", authDetails.Type())
	}

	if authDetails.Identifier() != "random_identifier" {
		t.Errorf("Identifier() = %v, want random_identifier",
			authDetails.Identifier())
	}
	if diff := cmp.Diff(
		authDetails.Actions(),
		[]string{"random_action"},
	); diff != "" {
		t.Errorf(diff)
	}
}
