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
	Type                 goidc.GrantType
	Subject              string
	Username             string
	ClientID             string
	Scopes               string
	AuthDetails          []goidc.AuthDetail
	Resources            goidc.Resources
	Nonce                string
	AuthCode             string
	AuthCodeExpiresAt    int
	PreAuthCode          string
	DeviceCode           string
	DeviceCodeExpiresAt  int
	AuthReqID            string
	AuthReqIDExpiresAt   int
	AuthReqIDConsumedAt  int
	JWKThumbprint        string
	ClientCertThumbprint string
	Actor                *goidc.Actor
	AuthParams           goidc.AuthorizationParameters
	Store                map[string]any
}

func NewGrant(ctx oidc.Context, c *goidc.Client, opts GrantOptions) (*goidc.Grant, error) {
	grant := &goidc.Grant{
		ID:                  ctx.GrantID(),
		AuthCode:            opts.AuthCode,
		AuthCodeExpiresAt:   opts.AuthCodeExpiresAt,
		PreAuthCode:         opts.PreAuthCode,
		DeviceCode:          opts.DeviceCode,
		DeviceCodeExpiresAt: opts.DeviceCodeExpiresAt,
		AuthReqID:           opts.AuthReqID,
		AuthReqIDExpiresAt:  opts.AuthReqIDExpiresAt,
		AuthReqIDConsumedAt: opts.AuthReqIDConsumedAt,
		Subject:             opts.Subject,
		Username:            opts.Username,
		ClientID:            opts.ClientID,
		Actor:               opts.Actor,
		Scopes:              opts.Scopes,
		Store:               opts.Store,
		JWKThumbprint:       opts.JWKThumbprint,
		CertThumbprint:      opts.ClientCertThumbprint,
		AuthParams:          opts.AuthParams,
		CreatedAt:           timeutil.TimestampNow(),
	}
	if ctx.RARIsEnabled {
		grant.AuthDetails = opts.AuthDetails
	}
	if ctx.ResourceIndicatorsIsEnabled {
		grant.Resources = opts.Resources
	}
	if err := ctx.HandleGrant(opts.Type, grant); err != nil {
		return nil, err
	}

	if slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) && slices.Contains(c.GrantTypes, goidc.GrantRefreshToken) &&
		ctx.RefreshTokenShouldIssue(c, grant) && opts.Subject != c.ID {
		grant.RefreshToken = ctx.RefreshToken()
		if ctx.RefreshTokenLifetimeSecs != 0 {
			grant.RefreshTokenExpiresAt = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
		}
	}

	if err := ctx.SaveGrant(grant); err != nil {
		return nil, err
	}

	return grant, nil
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
	authDetails  []goidc.AuthDetail
	assertion    string
	authReqID    string
	preAuthCode  string
	txCode       string
	deviceCode   string
	// audience is the logical name of the target service where the client
	// intends to use the requested security token.
	// Multiple audience values indicate the token is intended for multiple
	// audiences.
	audience []string
	// requestedTokenType is an identifier for the type of the requested security token.
	requestedTokenType goidc.TokenTypeIdentifier
	// subjectToken is a security token that represents the identity of the
	// party on behalf of whom the request is being made.
	subjectToken string
	// subjectTokenType is an identifier that indicates the type of the security
	// token in the "subject_token" parameter.
	subjectTokenType goidc.TokenTypeIdentifier
	// actorToken is a security token that represents the identity of the acting party.
	actorToken string
	// actorTokenType is an identifier that indicates the type of the security
	// token in the "actor_token" parameter.
	actorTokenType goidc.TokenTypeIdentifier
}

func newRequest(r *http.Request) request {
	req := request{
		grantType:          goidc.GrantType(r.PostFormValue("grant_type")),
		scopes:             r.PostFormValue("scope"),
		code:               r.PostFormValue("code"),
		redirectURI:        r.PostFormValue("redirect_uri"),
		refreshToken:       r.PostFormValue("refresh_token"),
		codeVerifier:       r.PostFormValue("code_verifier"),
		resources:          r.PostForm["resource"],
		assertion:          r.PostFormValue("assertion"),
		authReqID:          r.PostFormValue("auth_req_id"),
		preAuthCode:        r.PostFormValue("pre-authorized_code"),
		txCode:             r.PostFormValue("tx_code"),
		deviceCode:         r.PostFormValue("device_code"),
		subjectToken:       r.PostFormValue("subject_token"),
		subjectTokenType:   goidc.TokenTypeIdentifier(r.PostFormValue("subject_token_type")),
		actorToken:         r.PostFormValue("actor_token"),
		actorTokenType:     goidc.TokenTypeIdentifier(r.PostFormValue("actor_token_type")),
		audience:           r.PostForm["audience"],
		requestedTokenType: goidc.TokenTypeIdentifier(r.PostFormValue("requested_token_type")),
	}

	if authDetails := r.PostFormValue("authorization_details"); authDetails != "" {
		var authDetailsObject []goidc.AuthDetail
		if err := json.Unmarshal([]byte(authDetails), &authDetailsObject); err == nil {
			req.authDetails = authDetailsObject
		}
	}

	return req
}

type response struct {
	AccessToken          string             `json:"access_token,omitempty"`
	IDToken              string             `json:"id_token,omitempty"`
	RefreshToken         string             `json:"refresh_token,omitempty"`
	ExpiresIn            int                `json:"expires_in,omitempty"`
	TokenType            goidc.TokenType    `json:"token_type,omitempty"`
	Scopes               string             `json:"scope,omitempty"`
	AuthorizationDetails []goidc.AuthDetail `json:"authorization_details,omitempty"`
	Resources            goidc.Resources    `json:"resources,omitempty"`
	// IssuedTokenType is an identifier for the representation of the issued security token.
	IssuedTokenType goidc.TokenTypeIdentifier `json:"issued_token_type,omitempty"`
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

type bindindValidationOptions struct {
	tlsIsRequired     bool
	tlsCertThumbprint string
	dpopIsRequired    bool
	dpopJWKThumbprint string
}
