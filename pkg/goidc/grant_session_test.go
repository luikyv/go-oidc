package goidc_test

import (
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestIsRefreshSessionExpired(t *testing.T) {
	// Given.
	session := goidc.GrantSession{
		ExpiresAtTimestamp: goidc.TimestampNow() - 1,
	}

	// Then.
	assert.True(t, session.IsRefreshSessionExpired())
}

func TestHasLastTokenExpired(t *testing.T) {
	// Given.
	session := goidc.GrantSession{
		LastTokenIssuedAtTimestamp: goidc.TimestampNow() - 1,
	}

	// Then.
	assert.True(t, session.HasLastTokenExpired())
}
