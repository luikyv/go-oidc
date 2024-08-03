package authorize

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthorizationRequest(t *testing.T) {
	// Given.
	params := url.Values{}
	params.Set("client_id", "random_client_id")
	params.Set("request_uri", "random_request_uri")
	params.Set("request", "random_request_object")
	params.Set("redirect_uri", "random_redirect_uri")
	params.Set("response_mode", "query")
	params.Set("response_type", "code")
	params.Set("scope", "openid")
	params.Set("state", "random_state")
	params.Set("nonce", "random_nonce")
	params.Set("code_challenge", "random_code_challenge")
	params.Set("code_challenge_method", "S256")
	params.Set("prompt", "login")
	params.Set("display", "page")
	params.Set("acr_values", "0 1")
	params.Set("max_age", "0")
	params.Set("claims", "{}")
	params.Set("authorization_details", "[]")

	reqURL, _ := url.Parse("https://example.com/authorize")
	reqURL.RawQuery = params.Encode()
	req := httptest.NewRequest(http.MethodPost, reqURL.String(), nil)

	// When.
	authorizationReq := newAuthorizationRequest(req)

	// Then.
	assert.Equal(t, "random_client_id", authorizationReq.ClientID)
	assert.Equal(t, "random_request_uri", authorizationReq.RequestURI)
	assert.Equal(t, "random_request_object", authorizationReq.RequestObject)
	assert.Equal(t, "random_redirect_uri", authorizationReq.RedirectURI)
	assert.Equal(t, goidc.ResponseModeQuery, authorizationReq.ResponseMode)
	assert.Equal(t, goidc.ResponseTypeCode, authorizationReq.ResponseType)
	assert.Equal(t, "openid", authorizationReq.Scopes)
	assert.Equal(t, "random_state", authorizationReq.State)
	assert.Equal(t, "random_nonce", authorizationReq.Nonce)
	assert.Equal(t, "random_code_challenge", authorizationReq.CodeChallenge)
	assert.Equal(t, goidc.CodeChallengeMethodSHA256, authorizationReq.CodeChallengeMethod)
	assert.Equal(t, goidc.PromptTypeLogin, authorizationReq.Prompt)
	assert.Equal(t, goidc.DisplayValuePage, authorizationReq.Display)
	assert.Equal(t, "0 1", authorizationReq.ACRValues)
	require.NotNil(t, authorizationReq.MaxAuthnAgeSecs)
	assert.Equal(t, 0, *authorizationReq.MaxAuthnAgeSecs)
	require.NotNil(t, authorizationReq.Claims)
	require.NotNil(t, authorizationReq.AuthorizationDetails)
}

func TestNewPushedAuthorizationRequest(t *testing.T) {
	// Given.
	params := url.Values{}
	params.Set("client_id", "random_client_id")
	params.Set("request_uri", "random_request_uri")
	params.Set("request", "random_request_object")
	params.Set("redirect_uri", "random_redirect_uri")
	params.Set("response_mode", "query")
	params.Set("response_type", "code")
	params.Set("scope", "openid")
	params.Set("state", "random_state")
	params.Set("nonce", "random_nonce")
	params.Set("code_challenge", "random_code_challenge")
	params.Set("code_challenge_method", "S256")
	params.Set("prompt", "login")
	params.Set("display", "page")
	params.Set("acr_values", "0 1")
	params.Set("max_age", "0")
	params.Set("claims", "{}")
	params.Set("authorization_details", "[]")

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// When.
	pushedAuthReq := newPushedAuthorizationRequest(req)

	// Then.
	assert.Equal(t, "random_client_id", pushedAuthReq.ClientID)
	assert.Equal(t, "random_request_uri", pushedAuthReq.RequestURI)
	assert.Equal(t, "random_request_object", pushedAuthReq.RequestObject)
	assert.Equal(t, "random_redirect_uri", pushedAuthReq.RedirectURI)
	assert.Equal(t, goidc.ResponseModeQuery, pushedAuthReq.ResponseMode)
	assert.Equal(t, goidc.ResponseTypeCode, pushedAuthReq.ResponseType)
	assert.Equal(t, "openid", pushedAuthReq.Scopes)
	assert.Equal(t, "random_state", pushedAuthReq.State)
	assert.Equal(t, "random_nonce", pushedAuthReq.Nonce)
	assert.Equal(t, "random_code_challenge", pushedAuthReq.CodeChallenge)
	assert.Equal(t, goidc.CodeChallengeMethodSHA256, pushedAuthReq.CodeChallengeMethod)
	assert.Equal(t, goidc.PromptTypeLogin, pushedAuthReq.Prompt)
	assert.Equal(t, goidc.DisplayValuePage, pushedAuthReq.Display)
	assert.Equal(t, "0 1", pushedAuthReq.ACRValues)
	require.NotNil(t, pushedAuthReq.MaxAuthnAgeSecs)
	assert.Equal(t, 0, *pushedAuthReq.MaxAuthnAgeSecs)
	require.NotNil(t, pushedAuthReq.Claims)
	require.NotNil(t, pushedAuthReq.AuthorizationDetails)
}
