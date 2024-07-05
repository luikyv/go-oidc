package goidc_test

import (
	"slices"
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestScopes_GetIDs_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
	})

	// When.
	scopeIDs := scopes.GetIDs()

	// Then.
	if len(scopeIDs) != 2 {
		t.Error("there should be two ids")
		return
	}

	if !slices.Contains(scopeIDs, "scope1") || !slices.Contains(scopeIDs, "scope2") {
		t.Error("missing scopes")
		return
	}
}

func TestScopes_GetSubSet_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
		goidc.NewScope("scope3"),
	})

	// When.
	scopeSubSet := scopes.GetSubSet([]string{"scope1", "scope2"})

	// Then.
	if len(scopeSubSet) != 2 {
		t.Error("there should be two scopes")
		return
	}

	scopeSubSetIDs := []string{scopeSubSet[0].ID, scopeSubSet[1].ID}
	if !slices.Contains(scopeSubSetIDs, "scope1") || !slices.Contains(scopeSubSetIDs, "scope2") {
		t.Error("missing scopes")
		return
	}
}

func TestScopes_Contains_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.NewScope("scope1"),
		goidc.NewScope("scope2"),
	})

	// When.
	contains := scopes.Contains("scope1")

	// Then.
	if !contains {
		t.Error("scope1 should be found")
		return
	}

	// When.
	contains = scopes.Contains("invalid_scope")

	// Then.
	if contains {
		t.Error("invalid_scope should not be found")
		return
	}
}

func TestScopes_ContainsOpenID_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.ScopeOpenID,
	})

	// When.
	contains := scopes.ContainsOpenID()

	// Then.
	if !contains {
		t.Error("openid should be found")
		return
	}

	// Given.
	scopes = goidc.Scopes([]goidc.Scope{})

	// When.
	contains = scopes.ContainsOpenID()

	// Then.
	if contains {
		t.Error("openid should not be found")
		return
	}
}

func TestScopes_String_HappyPath(t *testing.T) {
	// Given.
	scopes := goidc.Scopes([]goidc.Scope{
		goidc.ScopeOpenID,
		goidc.ScopeEmail,
	})

	// When.
	scopeString := scopes.String()

	// Then.
	if scopeString != "openid email" {
		t.Error("invalid scope string")
		return
	}
}
