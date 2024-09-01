package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestSaveAndGetParameter_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	for i := 0; i < 2; i++ {
		// When.
		session.StoreParameter("key", "value")
		// Then.
		if session.Store["key"] != "value" {
			t.Errorf("Store[\"key\"] = %v, want %s", session.Store["key"], "value")
		}
	}
}

func TestAddTokenClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.SetTokenClaim("random_claim", "random_value")
		// Then.
		if session.AdditionalTokenClaims["random_claim"] != "random_value" {
			t.Errorf("AdditionalTokenClaims[\"random_claim\"] = %v, want %s",
				session.AdditionalTokenClaims["random_claim"], "random_value")
		}
	}
}

func TestAddIDTokenClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.SetIDTokenClaim("random_claim", "random_value")
		// Then.
		if session.AdditionalIDTokenClaims["random_claim"] != "random_value" {
			t.Errorf("AdditionalIDTokenClaims[\"random_claim\"] = %v, want %s",
				session.AdditionalIDTokenClaims["random_claim"], "random_value")
		}
	}
}

func TestAddUserInfoClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.SetUserInfoClaim("random_claim", "random_value")
		// Then.
		if session.AdditionalUserInfoClaims["random_claim"] != "random_value" {
			t.Errorf("AdditionalUserInfoClaims[\"random_claim\"] = %v, want %s",
				session.AdditionalUserInfoClaims["random_claim"], "random_value")
		}
	}
}

func TestIsExpired(t *testing.T) {
	// Given.
	now := timeutil.TimestampNow()
	session := goidc.AuthnSession{
		ExpiresAtTimestamp: now - 10,
	}
	// Then.
	if !session.IsExpired() {
		t.Errorf("IsExpired() = %t, want true", session.IsExpired())
	}
}
