package goidc_test

import (
	"testing"
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestSaveAndGetParameter_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	for i := 0; i < 2; i++ {
		// When.
		session.StoreParameter("key", "value")
		// Then.
		assert.Equal(t, "value", session.Store["key"], "the claim was not added")
	}
}

func TestAddTokenClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.SetClaimToken("random_claim", "random_value")
		// Then.
		assert.Equal(t, "random_value", session.AdditionalTokenClaims["random_claim"])
	}
}

func TestAddIDTokenClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.SetClaimIDToken("random_claim", "random_value")
		// Then.
		assert.Equal(t, "random_value", session.AdditionalIDTokenClaims["random_claim"])
	}
}

func TestAddUserInfoClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.SetClaimUserInfo("random_claim", "random_value")
		// Then.
		assert.Equal(t, "random_value", session.AdditionalUserInfoClaims["random_claim"])
	}
}

func TestIsExpired(t *testing.T) {
	// Given.
	now := time.Now().Unix()
	session := goidc.AuthnSession{
		ExpiresAtTimestamp: now - 10,
	}
	// Then.
	assert.True(t, session.IsExpired())
}
