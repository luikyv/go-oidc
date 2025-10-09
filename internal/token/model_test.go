package token

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestNewRequest(t *testing.T) {
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
	params.Set("device_code", "random_device_code")

	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBufferString(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// When.
	tokenReq := newRequest(req)

	// Then.
	want := request{
		grantType:         goidc.GrantAuthorizationCode,
		scopes:            "openid",
		authorizationCode: "random_code",
		redirectURI:       "https://example.com",
		refreshToken:      "random_refresh_token",
		codeVerifier:      "random_code_verifier",
		clientID:          "random_client_id",
		deviceCode:        "random_device_code",
	}
	if diff := cmp.Diff(tokenReq, want, cmp.AllowUnexported(request{})); diff != "" {
		t.Error(diff)
	}
}
