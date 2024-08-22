package token

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/clientauthn"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type GrantOptions struct {
	GrantType                   goidc.GrantType
	Subject                     string
	ClientID                    string
	GrantedScopes               string
	GrantedAuthorizationDetails []goidc.AuthorizationDetail
	AdditionalIDTokenClaims     map[string]any
	AdditionalUserInfoClaims    map[string]any
	goidc.TokenOptions
}

func NewGrantOptions(grantSession goidc.GrantSession) GrantOptions {
	return GrantOptions{
		GrantType:                   grantSession.GrantType,
		Subject:                     grantSession.Subject,
		ClientID:                    grantSession.ClientID,
		GrantedScopes:               grantSession.GrantedScopes,
		GrantedAuthorizationDetails: grantSession.GrantedAuthorizationDetails,
		AdditionalIDTokenClaims:     grantSession.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims:    grantSession.AdditionalUserInfoClaims,
		TokenOptions:                grantSession.TokenOptions,
	}
}

type Token struct {
	ID                    string
	Format                goidc.TokenFormat
	Value                 string
	Type                  goidc.TokenType
	JWKThumbprint         string
	CertificateThumbprint string
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

func newIDTokenOptions(grantOpts GrantOptions) IDTokenOptions {
	return IDTokenOptions{
		Subject:                 grantOpts.Subject,
		AdditionalIDTokenClaims: grantOpts.AdditionalIDTokenClaims,
	}
}

type dpopValidationOptions struct {
	// AccessToken should be filled when the DPoP "ath" claim is expected and should be validated.
	AccessToken   string
	JWKThumbprint string
}

type dpopClaims struct {
	HTTPMethod      string `json:"htm"`
	HTTPURI         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
}

type request struct {
	GrantType         goidc.GrantType
	Scopes            string
	AuthorizationCode string
	RedirectURI       string
	RefreshToken      string
	CodeVerifier      string
	Resources         goidc.Resources
	clientauthn.Request
}

func newRequest(req *http.Request) request {
	return request{
		Request:           clientauthn.NewRequest(req),
		GrantType:         goidc.GrantType(req.PostFormValue("grant_type")),
		Scopes:            req.PostFormValue("scope"),
		AuthorizationCode: req.PostFormValue("code"),
		RedirectURI:       req.PostFormValue("redirect_uri"),
		RefreshToken:      req.PostFormValue("refresh_token"),
		CodeVerifier:      req.PostFormValue("code_verifier"),
		Resources:         req.PostForm["resource"],
	}
}

type response struct {
	AccessToken          string                      `json:"access_token"`
	IDToken              string                      `json:"id_token,omitempty"`
	RefreshToken         string                      `json:"refresh_token,omitempty"`
	ExpiresIn            int64                       `json:"expires_in"`
	TokenType            goidc.TokenType             `json:"token_type"`
	Scopes               string                      `json:"scope,omitempty"`
	AuthorizationDetails []goidc.AuthorizationDetail `json:"authorization_details,omitempty"`
}

type resultChannel struct {
	Result any
	Err    oidc.Error
}

type introspectionRequest struct {
	Token         string
	TokenTypeHint goidc.TokenTypeHint
	clientauthn.Request
}

func newIntrospectionRequest(req *http.Request) introspectionRequest {
	return introspectionRequest{
		Request:       clientauthn.NewRequest(req),
		Token:         req.PostFormValue("token"),
		TokenTypeHint: goidc.TokenTypeHint(req.PostFormValue("token_type_hint")),
	}
}

func NewGrantSession(grantOptions GrantOptions, token Token) *goidc.GrantSession {
	timestampNow := time.Now().Unix()
	return &goidc.GrantSession{
		ID:                          uuid.New().String(),
		TokenID:                     token.ID,
		JWKThumbprint:               token.JWKThumbprint,
		ClientCertThumbprint:        token.CertificateThumbprint,
		CreatedAtTimestamp:          timestampNow,
		LastTokenIssuedAtTimestamp:  timestampNow,
		ExpiresAtTimestamp:          timestampNow + grantOptions.LifetimeSecs,
		ActiveScopes:                grantOptions.GrantedScopes,
		GrantType:                   grantOptions.GrantType,
		Subject:                     grantOptions.Subject,
		ClientID:                    grantOptions.ClientID,
		GrantedScopes:               grantOptions.GrantedScopes,
		GrantedAuthorizationDetails: grantOptions.GrantedAuthorizationDetails,
		AdditionalIDTokenClaims:     grantOptions.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims:    grantOptions.AdditionalUserInfoClaims,
		TokenOptions:                grantOptions.TokenOptions,
	}
}
