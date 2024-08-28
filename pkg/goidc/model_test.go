package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestAddTokenClaims_HappyPath(t *testing.T) {
	// Given.
	tokenOptions := goidc.TokenOptions{}

	// When.
	tokenOptions = tokenOptions.WithClaims(map[string]any{
		"claim": "value",
	})
	// Then.
	assert.Equal(t, "value", tokenOptions.AdditionalClaims["claim"], "the claim was not added")

	// When.
	tokenOptions = tokenOptions.WithClaims(map[string]any{
		"claim": "value",
	})
	// Then.
	assert.Equal(t, "value", tokenOptions.AdditionalClaims["claim"], "the claim was not added")
}

func TestAuthorizationDetail_GetProperties_HappyPath(t *testing.T) {
	// Given.
	authDetails := goidc.AuthorizationDetail{
		"type":       "random_type",
		"identifier": "random_identifier",
		"actions":    []string{"random_action"},
	}

	// Then.
	assert.Equal(t, "random_type", authDetails.Type(), "type not as expected")
	assert.Equal(t, "random_identifier", authDetails.Identifier(), "identifier not as expected")
	assert.Contains(t, authDetails.Actions(), "random_action", "action not as expected")
}
