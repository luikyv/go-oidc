package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

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
}
