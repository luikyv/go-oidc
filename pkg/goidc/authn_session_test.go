package goidc_test

import (
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestAuthnSession_GetClaims_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}
	// When.
	_, ok := session.GetClaims()
	// Then.
	assert.False(t, ok, "no claims should be found")

	// Given.
	session.Claims = &goidc.ClaimsObject{}
	// When.
	_, ok = session.GetClaims()
	// Then.
	assert.True(t, ok, "he claims should be found")
}

func TestAuthnSession_GetAuthorizationDetails_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}
	// When.
	_, ok := session.GetAuthorizationDetails()
	// Then.
	assert.False(t, ok, "no details should be found")

	// Given.
	session.AuthorizationDetails = []goidc.AuthorizationDetail{}
	// When.
	_, ok = session.GetAuthorizationDetails()
	// Then.
	assert.True(t, ok, "the details should be found")
}

func TestAuthnSession_GetMaxAuthenticationAgeSecs_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}
	// When.
	_, ok := session.GetMaxAuthenticationAgeSecs()
	// Then.
	assert.False(t, ok, "no max_age should be found")

	// Given.
	maxAge := 1
	session.MaxAuthenticationAgeSecs = &maxAge
	// When.
	_, ok = session.GetMaxAuthenticationAgeSecs()
	// Then.
	assert.True(t, ok, "the max_age should be found")
}

func TestAuthnSession_GetACRValues_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}
	// When.
	_, ok := session.GetACRValues()
	// Then.
	assert.False(t, ok, "no acr_values should be found")

	// Given.
	session.ACRValues = "acr1 acr2"
	// When.
	acrValues, ok := session.GetACRValues()
	// Then.
	assert.True(t, ok, "the acr_values should be found")
	assert.Contains(t, acrValues, goidc.AuthenticationContextReference("acr1"), "missing acr1")
	assert.Contains(t, acrValues, goidc.AuthenticationContextReference("acr2"), "missing acr2")
}

func TestAuthnSession_SaveAndGetParameter_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	for i := 0; i < 2; i++ {
		// When.
		session.SaveParameter("key", "value")
		value, ok := session.GetParameter("key")
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
