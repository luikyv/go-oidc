package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestTokenIsExpired(t *testing.T) {
	// Given.
	token := goidc.Token{
		ExpiresAtTimestamp: timeutil.TimestampNow() - 1,
	}

	// Then.
	if !token.IsExpired() {
		t.Errorf("IsExpired() = %t, want true", token.IsExpired())
	}
}
