package goidc_test

import (
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndGetParameter_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	for i := 0; i < 2; i++ {
		// When.
		session.SaveParameter("key", "value")
		value, ok := session.Parameter("key")
		// Then.
		assert.True(t, ok, "the claim was not added")
		assert.Equal(t, "value", value, "the claim was not added")
	}
}

func TestPush_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	requestURI, err := session.Push(60)

	// Then.
	require.Nil(t, err, err)
	assert.NotEmpty(t, session.RequestURI, "the request URI was not initialized")
	assert.Equal(t, requestURI, session.RequestURI)
	assert.Equal(t, goidc.TimestampNow()+60, session.ExpiresAtTimestamp, "the session expiry time was not updated")
}

func TestStart_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI: "request_uri",
		},
	}

	// When.
	err := session.Start("policy_id", 60)

	// Then.
	require.Nil(t, err, err)
	assert.Equal(t, "policy_id", session.PolicyID, "the policy ID was not initialized")
	assert.NotEmpty(t, session.CallbackID, "the callback ID was not initialized")
	assert.Empty(t, session.RequestURI, "the request_uri was not erased")
	assert.Equal(t, goidc.TimestampNow()+60, session.ExpiresAtTimestamp, "the session expiry time was not updated")
}

func TestInitAuthorizationCode_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	err := session.InitAuthorizationCode()

	// Then.
	require.Nil(t, err, err)
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code was not initialized")

	goidc.AssertTimestampWithin(t, goidc.TimestampNow()+goidc.AuthorizationCodeLifetimeSecs, session.ExpiresAtTimestamp,
		"the session expiry time was not updated")
}

func TestAddTokenClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.AddTokenClaim("random_claim", "random_value")
		// Then.
		assert.Equal(t, "random_value", session.AdditionalTokenClaims["random_claim"])
	}
}

func TestAddIDTokenClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.AddIDTokenClaim("random_claim", "random_value")
		// Then.
		assert.Equal(t, "random_value", session.AdditionalIDTokenClaims["random_claim"])
	}
}

func TestAddUserInfoClaim(t *testing.T) {
	for i := 0; i < 2; i++ {
		// Given.
		session := goidc.AuthnSession{}
		// When.
		session.AddUserInfoClaim("random_claim", "random_value")
		// Then.
		assert.Equal(t, "random_value", session.AdditionalUserInfoClaims["random_claim"])
	}
}

func TestIsExpired(t *testing.T) {
	// Given.
	now := goidc.TimestampNow()
	session := goidc.AuthnSession{
		ExpiresAtTimestamp: now - 10,
	}
	// Then.
	assert.True(t, session.IsExpired())
}
