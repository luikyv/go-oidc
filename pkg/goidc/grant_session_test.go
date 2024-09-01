package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestIsRefreshSessionExpired(t *testing.T) {
	// Given.
	session := goidc.GrantSession{
		ExpiresAtTimestamp: timeutil.TimestampNow() - 1,
	}

	// Then.
	if !session.IsExpired() {
		t.Errorf("IsExpired() = %t, want true", session.IsExpired())
	}
}

func TestHasLastTokenExpired(t *testing.T) {
	// Given.
	session := goidc.GrantSession{
		LastTokenIssuedAtTimestamp: timeutil.TimestampNow() - 1,
	}

	// Then.
	if !session.HasLastTokenExpired() {
		t.Errorf("HasLastTokenExpired() = %t, want true", session.HasLastTokenExpired())
	}
}
