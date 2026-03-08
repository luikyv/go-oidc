package token

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type GrantOptions struct {
	AuthCode             string
	Type                 goidc.GrantType
	Subject              string
	ClientID             string
	Scopes               string
	AuthDetails          []goidc.AuthorizationDetail
	Resources            goidc.Resources
	Nonce                string
	JWKThumbprint        string
	ClientCertThumbprint string
	Store                map[string]any
}

func NewGrant(ctx oidc.Context, c *goidc.Client, opts GrantOptions) (*goidc.Grant, error) {
	grant := &goidc.Grant{
		ID:                   ctx.GrantID(),
		AuthCode:             opts.AuthCode,
		Type:                 opts.Type,
		Subject:              opts.Subject,
		ClientID:             opts.ClientID,
		Scopes:               opts.Scopes,
		Nonce:                opts.Nonce,
		Store:                opts.Store,
		JWKThumbprint:        opts.JWKThumbprint,
		ClientCertThumbprint: opts.ClientCertThumbprint,
		CreatedAtTimestamp:   timeutil.TimestampNow(),
	}
	if ctx.RichAuthorizationIsEnabled {
		grant.AuthDetails = opts.AuthDetails
	}
	if ctx.ResourceIndicatorsIsEnabled {
		grant.Resources = opts.Resources
	}
	if err := ctx.HandleGrant(grant); err != nil {
		return nil, err
	}

	if slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) &&
		slices.Contains(c.GrantTypes, goidc.GrantRefreshToken) &&
		ctx.ShouldIssueRefreshToken(c, grant) &&
		grant.Type != goidc.GrantClientCredentials && grant.Type != goidc.GrantImplicit {
		grant.RefreshToken = ctx.RefreshToken()
		grant.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	return grant, nil
}

type Options struct {
	Scopes      string
	AuthDetails []goidc.AuthorizationDetail
	Resources   goidc.Resources
}

// Issue creates a new access token for the grant, persists both the grant and
// token, and returns the token and its serialized value.
func Issue(ctx oidc.Context, grant *goidc.Grant, c *goidc.Client, opts *Options) (*goidc.Token, string, error) {
	if opts == nil {
		opts = &Options{}
	}

	tknOpts := ctx.TokenOptions(grant, c)
	now := timeutil.TimestampNow()
	tkn := &goidc.Token{
		GrantID:              grant.ID,
		Subject:              grant.Subject,
		ClientID:             grant.ClientID,
		Scopes:               grant.Scopes,
		AuthDetails:          grant.AuthDetails,
		Resources:            grant.Resources,
		JWKThumbprint:        grant.JWKThumbprint,
		ClientCertThumbprint: grant.ClientCertThumbprint,
		CreatedAtTimestamp:   now,
		ExpiresAtTimestamp:   now + tknOpts.LifetimeSecs,
		Format:               tknOpts.Format,
		SigAlg:               tknOpts.JWTSigAlg,
	}
	if tknOpts.Format == goidc.TokenFormatOpaque {
		tkn.ID = ctx.OpaqueToken()
	} else {
		tkn.ID = ctx.JWTID()
	}
	if tkn.JWKThumbprint != "" {
		tkn.Type = goidc.TokenTypeDPoP
	} else {
		tkn.Type = goidc.TokenTypeBearer
	}
	if opts.Scopes != "" {
		tkn.Scopes = opts.Scopes
	}
	if ctx.RichAuthorizationIsEnabled && opts.AuthDetails != nil {
		tkn.AuthDetails = opts.AuthDetails
	}
	if ctx.ResourceIndicatorsIsEnabled && opts.Resources != nil {
		tkn.Resources = opts.Resources
	}

	tokenValue, err := makeAccessToken(ctx, tkn, grant)
	if err != nil {
		return nil, "", err
	}
	if grant.ExpiresAtTimestamp == 0 {
		grant.ExpiresAtTimestamp = tkn.ExpiresAtTimestamp
	}
	if err := ctx.SaveGrant(grant); err != nil {
		return nil, "", err
	}
	if err := ctx.SaveToken(tkn); err != nil {
		return nil, "", err
	}

	return tkn, tokenValue, nil
}

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
	Claims            map[string]any
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
