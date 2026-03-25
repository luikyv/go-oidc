package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestStoreParameter(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.StoreParameter("key", "value")

	// Then.
	if session.Store["key"] != "value" {
		t.Errorf("Store[\"key\"] = %v, want %s", session.Store["key"], "value")
	}
}

func TestStoreParameter_Overwrite(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}
	session.StoreParameter("key", "old")

	// When.
	session.StoreParameter("key", "new")

	// Then.
	if session.Store["key"] != "new" {
		t.Errorf("Store[\"key\"] = %v, want %s", session.Store["key"], "new")
	}
}

func TestStoredParameter(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}
	session.StoreParameter("key", "value")

	// When.
	got := session.StoredParameter("key")

	// Then.
	if got != "value" {
		t.Errorf("StoredParameter(\"key\") = %v, want %s", got, "value")
	}
}

func TestStoredParameter_Missing(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	got := session.StoredParameter("missing")

	// Then.
	if got != nil {
		t.Errorf("StoredParameter(\"missing\") = %v, want nil", got)
	}
}

func TestAuthnSessionSetUserID(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.SetUserID("user123")

	// Then.
	if session.Subject != "user123" {
		t.Errorf("Subject = %s, want user123", session.Subject)
	}
}

func TestAuthnSessionGrantScopes(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.GrantScopes("openid profile")

	// Then.
	if session.GrantedScopes != "openid profile" {
		t.Errorf("GrantedScopes = %s, want openid profile", session.GrantedScopes)
	}
}

func TestAuthnSessionGrantAuthorizationDetails(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}
	details := []goidc.AuthDetail{
		{"type": "payment", "amount": 100},
	}

	// When.
	session.GrantAuthorizationDetails(details)

	// Then.
	if len(session.GrantedAuthDetails) != 1 {
		t.Fatalf("len(GrantedAuthDetails) = %d, want 1", len(session.GrantedAuthDetails))
	}
	if session.GrantedAuthDetails[0].Type() != "payment" {
		t.Errorf("Type() = %s, want payment", session.GrantedAuthDetails[0].Type())
	}
}

func TestAuthnSessionGrantResources(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.GrantResources([]string{"https://api.example.com"})

	// Then.
	if len(session.GrantedResources) != 1 || session.GrantedResources[0] != "https://api.example.com" {
		t.Errorf("GrantedResources = %v, want [https://api.example.com]", session.GrantedResources)
	}
}

func TestAuthnSessionIsExpired(t *testing.T) {
	now := timeutil.TimestampNow()

	testCases := []struct {
		name      string
		expiresAt int
		want      bool
	}{
		{"expired", now - 10, true},
		{"exactly now", now, true},
		{"not expired", now + 10, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Given.
			session := goidc.AuthnSession{
				ExpiresAtTimestamp: tc.expiresAt,
			}

			// When.
			got := session.IsExpired()

			// Then.
			if got != tc.want {
				t.Errorf("IsExpired() = %t, want %t", got, tc.want)
			}
		})
	}
}
