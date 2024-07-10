package goidc_test

import (
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestAuthnSession_SaveAndGetParameter_HappyPath(t *testing.T) {
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

func TestAuthnSession_Push_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.Push(60)

	// Then.
	assert.NotEmpty(t, session.RequestURI, "the request URI was not initialized")
	assert.Equal(t, goidc.TimestampNow()+60, session.ExpiresAtTimestamp, "the session expiry time was not updated")
}

func TestAuthnSession_Start_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI: "request_uri",
		},
	}

	// When.
	session.Start("policy_id", 60)

	// Then.
	assert.Equal(t, "policy_id", session.PolicyID, "the policy ID was not initialized")
	assert.NotEmpty(t, session.CallbackID, "the callback ID was not initialized")
	assert.Empty(t, session.RequestURI, "the request_uri was not erased")
	assert.Equal(t, goidc.TimestampNow()+60, session.ExpiresAtTimestamp, "the session expiry time was not updated")
}

func TestAuthnSession_InitAuthorizationCode_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.InitAuthorizationCode()

	// Then.
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code was not initialized")
	assert.Equal(t, goidc.TimestampNow(), session.AuthorizationCodeIssuedAt, "the authorization code issuance time was not initialized")
	assert.Equal(t, goidc.TimestampNow()+goidc.AuthorizationCodeLifetimeSecs, session.ExpiresAtTimestamp, "the session expiry time was not updated")
}
