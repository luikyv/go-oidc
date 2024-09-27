package token

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Token struct {
	ID           string
	Format       goidc.TokenFormat
	Value        string
	Type         goidc.TokenType
	LifetimeSecs int
}

type IDTokenOptions struct {
	Subject                 string
	AdditionalIDTokenClaims map[string]any
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implicit grant.
	AccessToken       string
	AuthorizationCode string
	State             string
}

func newIDTokenOptions(grantInfo goidc.GrantInfo) IDTokenOptions {
	return IDTokenOptions{
		Subject:                 grantInfo.Subject,
		AdditionalIDTokenClaims: grantInfo.AdditionalIDTokenClaims,
	}
}

type request struct {
	grantType         goidc.GrantType
	scopes            string
	authorizationCode string
	redirectURI       string
	refreshToken      string
	codeVerifier      string
	resources         goidc.Resources
}

func newRequest(req *http.Request) request {
	return request{
		grantType:         goidc.GrantType(req.PostFormValue("grant_type")),
		scopes:            req.PostFormValue("scope"),
		authorizationCode: req.PostFormValue("code"),
		redirectURI:       req.PostFormValue("redirect_uri"),
		refreshToken:      req.PostFormValue("refresh_token"),
		codeVerifier:      req.PostFormValue("code_verifier"),
		resources:         req.PostForm["resource"],
	}
}

type response struct {
	AccessToken          string                      `json:"access_token"`
	IDToken              string                      `json:"id_token,omitempty"`
	RefreshToken         string                      `json:"refresh_token,omitempty"`
	ExpiresIn            int                         `json:"expires_in"`
	TokenType            goidc.TokenType             `json:"token_type"`
	Scopes               string                      `json:"scope,omitempty"`
	AuthorizationDetails []goidc.AuthorizationDetail `json:"authorization_details,omitempty"`
	Resources            goidc.Resources             `json:"resources,omitempty"`
}

type queryRequest struct {
	token         string
	tokenTypeHint goidc.TokenTypeHint
}

func newQueryRequest(req *http.Request) queryRequest {
	return queryRequest{
		token:         req.PostFormValue("token"),
		tokenTypeHint: goidc.TokenTypeHint(req.PostFormValue("token_type_hint")),
	}
}

func NewGrantSession(grantInfo goidc.GrantInfo, token Token) *goidc.GrantSession {
	timestampNow := timeutil.TimestampNow()
	return &goidc.GrantSession{
		ID:                          uuid.New().String(),
		TokenID:                     token.ID,
		CreatedAtTimestamp:          timestampNow,
		LastTokenExpiresAtTimestamp: timestampNow + token.LifetimeSecs,
		ExpiresAtTimestamp:          timestampNow + token.LifetimeSecs,
		GrantInfo:                   grantInfo,
	}
}
