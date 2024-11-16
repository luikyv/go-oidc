package token

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/dpop"
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
	RefreshToken      string
	AuthReqID         string
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
	authDetails       []goidc.AuthorizationDetail
	assertion         string
	authReqID         string
}

func newRequest(r *http.Request) request {
	req := request{
		grantType:         goidc.GrantType(r.PostFormValue("grant_type")),
		scopes:            r.PostFormValue("scope"),
		authorizationCode: r.PostFormValue("code"),
		redirectURI:       r.PostFormValue("redirect_uri"),
		refreshToken:      r.PostFormValue("refresh_token"),
		codeVerifier:      r.PostFormValue("code_verifier"),
		resources:         r.PostForm["resource"],
		assertion:         r.PostFormValue("assertion"),
		authReqID:         r.PostFormValue("auth_req_id"),
	}

	if authDetails := r.PostFormValue("authorization_details"); authDetails != "" {
		var authDetailsObject []goidc.AuthorizationDetail
		if err := json.Unmarshal([]byte(authDetails), &authDetailsObject); err == nil {
			req.authDetails = authDetailsObject
		}
	}

	return req
}

type response struct {
	AccessToken          string                      `json:"access_token,omitempty"`
	IDToken              string                      `json:"id_token,omitempty"`
	RefreshToken         string                      `json:"refresh_token,omitempty"`
	ExpiresIn            int                         `json:"expires_in,omitempty"`
	TokenType            goidc.TokenType             `json:"token_type,omitempty"`
	Scopes               string                      `json:"scope,omitempty"`
	AuthorizationDetails []goidc.AuthorizationDetail `json:"authorization_details,omitempty"`
	Resources            goidc.Resources             `json:"resources,omitempty"`
}

type cibaResponse struct {
	AuthReqID string `json:"auth_req_id,omitempty"`
	response
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

type bindindValidationsOptions struct {
	tlsIsRequired     bool
	tlsCertThumbprint string
	dpopIsRequired    bool
	dpop              dpop.ValidationOptions
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
