package goidc_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestIsRefreshSessionExpired(t *testing.T) {
	// Given.
	session := goidc.GrantSession{
		ExpiresAtTimestamp: timeutil.TimestampNow() - 1,
	}

	// Then.
	assert.True(t, session.IsExpired())
}

func TestHasLastTokenExpired(t *testing.T) {
	// Given.
	session := goidc.GrantSession{
		LastTokenIssuedAtTimestamp: timeutil.TimestampNow() - 1,
	}

	// Then.
	assert.True(t, session.HasLastTokenExpired())
}
