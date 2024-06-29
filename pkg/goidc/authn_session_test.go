package goidc_test

import (
	"testing"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestAuthnSession_GetClaims_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	_, ok := session.GetClaims()

	// Then.
	if ok {
		t.Error("no claims should be found")
		return
	}

	// Given.
	session.Claims = &goidc.ClaimsObject{}

	// When.
	_, ok = session.GetClaims()

	// Then.
	if !ok {
		t.Error("the claims should be found")
		return
	}
}

func TestAuthnSession_GetAuthorizationDetails_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	_, ok := session.GetAuthorizationDetails()

	// Then.
	if ok {
		t.Error("no details should be found")
		return
	}

	// Given.
	session.AuthorizationDetails = []goidc.AuthorizationDetail{}

	// When.
	_, ok = session.GetAuthorizationDetails()

	// Then.
	if !ok {
		t.Error("the details should be found")
		return
	}
}

func TestAuthnSession_GetMaxAuthenticationAgeSecs_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	_, ok := session.GetMaxAuthenticationAgeSecs()

	// Then.
	if ok {
		t.Error("no max_age should not be found")
		return
	}

	// Given.
	maxAge := 1
	session.MaxAuthenticationAgeSecs = &maxAge

	// When.
	_, ok = session.GetMaxAuthenticationAgeSecs()

	// Then.
	if !ok {
		t.Error("the max_age should be found")
		return
	}
}

func TestAuthnSession_GetACRValues_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	_, ok := session.GetACRValues()

	// Then.
	if ok {
		t.Error("no acr_values should not be found")
		return
	}

	// Given.
	session.ACRValues = "acr1 acr2"

	// When.
	acrValues, ok := session.GetACRValues()

	// Then.
	if !ok || acrValues[0] != "acr1" || acrValues[1] != "acr2" {
		t.Error("the acr_values should be found")
		return
	}
}

func TestAuthnSession_SaveAndGetParameter_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.SaveParameter("key", "value")
	value, ok := session.GetParameter("key")
	// Then.
	if !ok || value != "value" {
		t.Error("the claim was not added")
	}

	// When.
	session.SaveParameter("key", "value")
	value, ok = session.GetParameter("key")
	// Then.
	if !ok || value != "value" {
		t.Error("the claim was not added")
	}
}

func TestAuthnSession_Push_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.Push(60)

	// Then.
	if session.RequestURI == "" {
		t.Error("the request URI was not initialized")
		return
	}

	if session.ExpiresAtTimestamp != goidc.GetTimestampNow()+60 {
		t.Error("the session expiry time was not updated")
	}
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
	if session.PolicyID != "policy_id" {
		t.Error("the policy ID was not initialized")
		return
	}

	if session.CallbackID == "" {
		t.Error("the callback ID was not initialized")
		return
	}

	if session.RequestURI != "" {
		t.Error("the request_uri was not erased")
	}

	if session.ExpiresAtTimestamp != goidc.GetTimestampNow()+60 {
		t.Error("the session expiry time was not updated")
	}
}

func TestAuthnSession_InitAuthorizationCode_HappyPath(t *testing.T) {
	// Given.
	session := goidc.AuthnSession{}

	// When.
	session.InitAuthorizationCode()

	// Then.
	if session.AuthorizationCode == "" {
		t.Error("the authorization code was not initialized")
	}

	if session.AuthorizationCodeIssuedAt != goidc.GetTimestampNow() {
		t.Error("the authorization code issuance time was not initialized")
	}

	if session.ExpiresAtTimestamp != goidc.GetTimestampNow()+goidc.AuthorizationCodeLifetimeSecs {
		t.Error("the session expiry time was not updated")
	}
}
