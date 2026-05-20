package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestTokenLifetimeSecs(t *testing.T) {
	// Given.
	token := goidc.Token{
		CreatedAt: 1000,
		ExpiresAt: 4600,
	}

	// When.
	got := token.LifetimeSecs()

	// Then.
	if got != 3600 {
		t.Errorf("LifetimeSecs() = %d, want 3600", got)
	}
}
