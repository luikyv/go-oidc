package token

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/authn"
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

type DPoPJWTValidationOptions struct {
	// AccessToken should be filled when the DPoP "ath" claim is expected and should be validated.
	AccessToken   string
	JWKThumbprint string
}

type dpopJWTClaims struct {
	HTTPMethod      string `json:"htm"`
	HTTPURI         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
}

type tokenRequest struct {
	GrantType         goidc.GrantType
	Scopes            string
	AuthorizationCode string
	RedirectURI       string
	RefreshToken      string
	CodeVerifier      string
	authn.ClientAuthnRequest
}

func newTokenRequest(req *http.Request) tokenRequest {
	return tokenRequest{
		ClientAuthnRequest: authn.NewClientAuthnRequest(req),
		GrantType:          goidc.GrantType(req.PostFormValue("grant_type")),
		Scopes:             req.PostFormValue("scope"),
		AuthorizationCode:  req.PostFormValue("code"),
		RedirectURI:        req.PostFormValue("redirect_uri"),
		RefreshToken:       req.PostFormValue("refresh_token"),
		CodeVerifier:       req.PostFormValue("code_verifier"),
	}
}

type tokenResponse struct {
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

type tokenIntrospectionRequest struct {
	authn.ClientAuthnRequest
	Token         string
	TokenTypeHint goidc.TokenTypeHint
}

func newTokenIntrospectionRequest(req *http.Request) tokenIntrospectionRequest {
	return tokenIntrospectionRequest{
		ClientAuthnRequest: authn.NewClientAuthnRequest(req),
		Token:              req.PostFormValue("token"),
		TokenTypeHint:      goidc.TokenTypeHint(req.PostFormValue("token_type_hint")),
	}
}

type Confirmation struct {
	JWKThumbprint               string `json:"jkt"`
	ClientCertificateThumbprint string `json:"x5t#S256"`
}

func NewGrantSession(grantOptions GrantOptions, token Token) *goidc.GrantSession {
	timestampNow := time.Now().Unix()
	return &goidc.GrantSession{
		ID:                          uuid.New().String(),
		TokenID:                     token.ID,
		JWKThumbprint:               token.JWKThumbprint,
		ClientCertificateThumbprint: token.CertificateThumbprint,
		CreatedAtTimestamp:          timestampNow,
		LastTokenIssuedAtTimestamp:  timestampNow,
		ExpiresAtTimestamp:          timestampNow + grantOptions.TokenLifetimeSecs,
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
