package goidc_test

import (
	"testing"
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestIsRefreshSessionExpired(t *testing.T) {
	// Given.
	session := goidc.GrantSession{
		ExpiresAtTimestamp: time.Now().Unix() - 1,
	}

	// Then.
	assert.True(t, session.IsExpired())
}

func TestHasLastTokenExpired(t *testing.T) {
	// Given.
	session := goidc.GrantSession{
		LastTokenIssuedAtTimestamp: time.Now().Unix() - 1,
	}

	// Then.
	assert.True(t, session.HasLastTokenExpired())
}
