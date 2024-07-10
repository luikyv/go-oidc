package goidc_test

import (
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestScopes_GetIDs_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
	})

	// When.
	scopeIDs := scopes.IDs()

	// Then.
	assert.Len(t, scopeIDs, 2, "there should be two ids")
	assert.Contains(t, scopeIDs, "scope1", "missing scope1")
	assert.Contains(t, scopeIDs, "scope1", "missing scope2")
}

func TestScopes_GetSubSet_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
		goidc.NewScope("scope3"),
	})

	// When.
	scopeSubSet := scopes.SubSet([]string{"scope1", "scope2"})

	// Then.
	assert.Len(t, scopeSubSet, 2, "there should be two scopes")
	scopeSubSetIDs := []string{scopeSubSet[0].ID, scopeSubSet[1].ID}
	assert.Contains(t, scopeSubSetIDs, "scope1", "missing scope1")
	assert.Contains(t, scopeSubSetIDs, "scope2", "missing scope2")
}

func TestScopes_Contains_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
	})

	// Then.
	assert.True(t, scopes.Contains("scope1"), "scope1 should be found")
	assert.False(t, scopes.Contains("invalid_scope"), "invalid_scope should not be found")
}

func TestScopes_ContainsOpenID_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.ScopeOpenID,
	})
	// Then.
	assert.True(t, scopes.ContainsOpenID(), "openid should be found")

	// Given.
	scopes = goidc.Scopes([]goidc.Scope{})
	// Then.
	assert.False(t, scopes.ContainsOpenID(), "openid should not be found")
}

func TestScopes_String_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.ScopeOpenID,
		goidc.ScopeEmail,
	})

	// When.
	assert.Equal(t, "openid email", scopes.String(), "invalid scope string")
}
