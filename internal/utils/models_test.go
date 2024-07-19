package utils_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientAuthnRequest(t *testing.T) {
	// Given.
	params := url.Values{}
	params.Set("client_id", "random_client_id")
	params.Set("client_secret", "random_client_secret")
	params.Set("client_assertion", "random_client_assertion")
	params.Set("client_assertion_type", "random_client_assertion_type")

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// When.
	clientAuthnReq := utils.NewClientAuthnRequest(req)

	// Then.
	assert.Equal(t, "random_client_id", clientAuthnReq.ClientID)
	assert.Equal(t, "random_client_secret", clientAuthnReq.ClientSecret)
	assert.Equal(t, "random_client_assertion", clientAuthnReq.ClientAssertion)
	assert.Equal(t, goidc.ClientAssertionType("random_client_assertion_type"), clientAuthnReq.ClientAssertionType)
}

func TestNewTokenRequest(t *testing.T) {
	// Given.
	params := url.Values{}
	params.Set("client_id", "random_client_id")
	params.Set("client_secret", "random_client_secret")
	params.Set("grant_type", "authorization_code")
	params.Set("scope", "openid")
	params.Set("code", "random_code")
	params.Set("redirect_uri", "https://example.com")
	params.Set("refresh_token", "random_refresh_token")
	params.Set("code_verifier", "random_code_verifier")

	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBufferString(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// When.
	tokenReq := utils.NewTokenRequest(req)

	// Then.
	assert.Equal(t, "random_client_id", tokenReq.ClientID)
	assert.Equal(t, "random_client_secret", tokenReq.ClientSecret)
	assert.Equal(t, goidc.GrantAuthorizationCode, tokenReq.GrantType)
	assert.Equal(t, "openid", tokenReq.Scopes)
	assert.Equal(t, "random_code", tokenReq.AuthorizationCode)
	assert.Equal(t, "https://example.com", tokenReq.RedirectURI)
	assert.Equal(t, "random_refresh_token", tokenReq.RefreshToken)
	assert.Equal(t, "random_client_secret", tokenReq.ClientSecret)
	assert.Equal(t, "random_code_verifier", tokenReq.CodeVerifier)
}

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
	authorizationReq := utils.NewAuthorizationRequest(req)

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
	pushedAuthReq := utils.NewPushedAuthorizationRequest(req)

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
