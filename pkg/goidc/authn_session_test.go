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
