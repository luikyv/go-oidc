package token_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

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
	tokenReq := token.NewRequest(req)

	// Then.
	assert.Equal(t, "random_client_id", tokenReq.ID)
	assert.Equal(t, "random_client_secret", tokenReq.Secret)
	assert.Equal(t, goidc.GrantAuthorizationCode, tokenReq.GrantType)
	assert.Equal(t, "openid", tokenReq.Scopes)
	assert.Equal(t, "random_code", tokenReq.AuthorizationCode)
	assert.Equal(t, "https://example.com", tokenReq.RedirectURI)
	assert.Equal(t, "random_refresh_token", tokenReq.RefreshToken)
	assert.Equal(t, "random_client_secret", tokenReq.Secret)
	assert.Equal(t, "random_code_verifier", tokenReq.CodeVerifier)
}
