package token

import (
	"encoding/json"
	"net/http"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type IDTokenOptions struct {
	Subject string
	Nonce   string
	// These values here below are intended to be hashed and placed in the ID token.
	// Then, the ID token can be used as a detached signature for the implicit grant.
	AccessToken       string
	AuthorizationCode string
	State             string
	RefreshToken      string
	AuthReqID         string
}

func newIDTokenOptions(grant *goidc.Grant) IDTokenOptions {
	return IDTokenOptions{
		Subject: grant.Subject,
		Nonce:   grant.Nonce,
	}
}

type request struct {
	grantType    goidc.GrantType
	scopes       string
	code         string
	redirectURI  string
	refreshToken string
	codeVerifier string
	resources    goidc.Resources
	authDetails  []goidc.AuthorizationDetail
	assertion    string
	authReqID    string
}

func newRequest(r *http.Request) request {
	req := request{
		grantType:    goidc.GrantType(r.PostFormValue("grant_type")),
		scopes:       r.PostFormValue("scope"),
		code:         r.PostFormValue("code"),
		redirectURI:  r.PostFormValue("redirect_uri"),
		refreshToken: r.PostFormValue("refresh_token"),
		codeVerifier: r.PostFormValue("code_verifier"),
		resources:    r.PostForm["resource"],
		assertion:    r.PostFormValue("assertion"),
		authReqID:    r.PostFormValue("auth_req_id"),
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
	dpopJWKThumbprint string
	// dpop              dpop.ValidationOptions
}

// tokenType derives the token type from PoP bindings.
func tokenType(token *goidc.Token) goidc.TokenType {
	if token.JWKThumbprint != "" {
		return goidc.TokenTypeDPoP
	}
	return goidc.TokenTypeBearer
}

// newToken builds a Token copying all common fields from the grant.
func newToken(ctx oidc.Context, grant *goidc.Grant, opts goidc.TokenOptions) *goidc.Token {
	now := timeutil.TimestampNow()
	id := ctx.OpaqueToken()
	if opts.Format == goidc.TokenFormatJWT {
		id = ctx.JWTID()
	}
	return &goidc.Token{
		ID:                   id,
		GrantID:              grant.ID,
		Subject:              grant.Subject,
		ClientID:             grant.ClientID,
		Scopes:               grant.Scopes,
		AuthDetails:          grant.AuthDetails,
		Resources:            grant.Resources,
		JWKThumbprint:        grant.JWKThumbprint,
		ClientCertThumbprint: grant.ClientCertThumbprint,
		CreatedAtTimestamp:   now,
		ExpiresAtTimestamp:   now + opts.LifetimeSecs,
		Format:               opts.Format,
		SigAlg:               opts.JWTSigAlg,
	}
}

// narrowToken overrides token scopes, authorization details, and resources
// with request-level values when present.
func narrowToken(ctx oidc.Context, tkn *goidc.Token, req request) {
	if req.scopes != "" {
		tkn.Scopes = req.scopes
	}
	if ctx.RichAuthorizationIsEnabled && req.authDetails != nil {
		tkn.AuthDetails = req.authDetails
	}
	if ctx.ResourceIndicatorsIsEnabled && req.resources != nil {
		tkn.Resources = req.resources
	}
}

// issueToken generates the access token value and persists the grant and token.
func issueToken(ctx oidc.Context, grant *goidc.Grant, tkn *goidc.Token) (string, error) {
	tokenValue, err := Make(ctx, tkn, grant)
	if err != nil {
		return "", err
	}
	if err := ctx.SaveGrant(grant); err != nil {
		return "", err
	}
	if err := ctx.SaveToken(tkn); err != nil {
		return "", err
	}
	return tokenValue, nil
}
