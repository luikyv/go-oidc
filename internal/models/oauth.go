package models

import (
	"errors"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GrantContext struct {
	Subject                 string
	ClientId                string
	Scopes                  []string
	GrantType               constants.GrantType
	Nonce                   string
	AdditionalTokenClaims   map[string]string
	AdditionalIdTokenClaims map[string]string
}

func NewClientCredentialsGrantGrantContextFromAuthnSession(client Client, req TokenRequest) GrantContext {
	return GrantContext{
		Subject:                 client.Id,
		ClientId:                client.Id,
		Scopes:                  unit.SplitStringWithSpaces(req.Scope),
		GrantType:               constants.ClientCredentials,
		AdditionalTokenClaims:   make(map[string]string),
		AdditionalIdTokenClaims: make(map[string]string),
	}
}

func NewAuthorizationCodeGrantGrantContextFromAuthnSession(session AuthnSession) GrantContext {
	return GrantContext{
		Subject:                 session.Subject,
		ClientId:                session.ClientId,
		Scopes:                  session.Scopes,
		GrantType:               constants.AuthorizationCode,
		Nonce:                   session.Nonce,
		AdditionalTokenClaims:   session.AdditionalTokenClaims,
		AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
	}
}

func NewRefreshTokenGrantGrantContextFromAuthnSession(session GrantSession) GrantContext {
	return GrantContext{
		Subject:               session.Subject,
		ClientId:              session.ClientId,
		Scopes:                session.Scopes,
		GrantType:             constants.RefreshToken,
		Nonce:                 session.Nonce,
		AdditionalTokenClaims: session.AdditionalTokenClaims,
	}
}

type ClientAuthnRequest struct {
	ClientIdBasicAuthn     string
	ClientSecretBasicAuthn string
	ClientIdPost           string                        `form:"client_id"`
	ClientSecretPost       string                        `form:"client_secret"`
	ClientAssertionType    constants.ClientAssertionType `form:"client_assertion_type"`
	ClientAssertion        string                        `form:"client_assertion"`
}

func (req ClientAuthnRequest) IsValid() error {

	// Either the client ID or the client assertion must be present to identity the client.
	if req.ClientIdBasicAuthn == "" && req.ClientIdPost == "" && req.ClientAssertion == "" {
		return issues.OAuthBaseError{
			ErrorCode:        constants.InvalidClient,
			ErrorDescription: "invalid client authentication",
		}
	}

	// Validate parameters for client secret basic authentication.
	if req.ClientIdBasicAuthn != "" && (req.ClientSecretBasicAuthn == "" || req.ClientIdPost != "" || req.ClientSecretPost != "" || req.ClientAssertionType != "" || req.ClientAssertion != "") {
		return issues.OAuthBaseError{
			ErrorCode:        constants.InvalidClient,
			ErrorDescription: "invalid client authentication",
		}
	}

	// Validate parameters for client secret post authentication.
	if req.ClientIdPost != "" && (req.ClientSecretPost == "" || req.ClientIdBasicAuthn != "" || req.ClientSecretBasicAuthn != "" || req.ClientAssertionType != "" || req.ClientAssertion != "") {
		return issues.OAuthBaseError{
			ErrorCode:        constants.InvalidClient,
			ErrorDescription: "invalid client authentication",
		}
	}

	// Validate parameters for private key jwt authentication.
	if req.ClientAssertion != "" && (req.ClientAssertionType != constants.JWTBearerAssertion || req.ClientIdBasicAuthn != "" || req.ClientSecretBasicAuthn != "" || req.ClientIdPost != "" || req.ClientSecretPost != "") {
		return issues.OAuthBaseError{
			ErrorCode:        constants.InvalidClient,
			ErrorDescription: "invalid client authentication",
		}
	}

	return nil
}

type TokenRequest struct {
	ClientAuthnRequest
	GrantType         constants.GrantType `form:"grant_type" binding:"required"`
	Scope             string              `form:"scope"`
	AuthorizationCode string              `form:"code"`
	RedirectUri       string              `form:"redirect_uri"`
	RefreshToken      string              `form:"refresh_token"`
	CodeVerifier      string              `form:"code_verifier"`
}

func (req TokenRequest) IsValid() error {

	if err := req.ClientAuthnRequest.IsValid(); err != nil {
		return err
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return errors.New("invalid code verifier")
	}

	// Validate parameters specific to each grant type.
	switch req.GrantType {
	case constants.ClientCredentials:
		if req.AuthorizationCode != "" || req.RedirectUri != "" || req.RefreshToken != "" {
			return errors.New("invalid parameter for client credentials grant")
		}
	case constants.AuthorizationCode:
		if req.AuthorizationCode == "" || req.RedirectUri == "" || req.RefreshToken != "" || req.Scope != "" {
			return errors.New("invalid parameter for authorization code grant")
		}
	case constants.RefreshToken:
		if req.RefreshToken == "" || req.AuthorizationCode != "" || req.RedirectUri != "" || req.Scope != "" {
			return errors.New("invalid parameter for refresh token grant")
		}
	default:
		return issues.OAuthBaseError{
			ErrorCode:        constants.UnsupportedGrantType,
			ErrorDescription: "unsupported grant type",
		}
	}

	return nil
}

type TokenResponse struct {
	AccessToken  string              `json:"access_token"`
	IdToken      string              `json:"id_token,omitempty"`
	RefreshToken string              `json:"refresh_token,omitempty"`
	ExpiresIn    int                 `json:"expires_in"`
	TokenType    constants.TokenType `json:"token_type"`
	Scope        string              `json:"scope,omitempty"`
}

type BaseAuthorizeRequest struct {
	RedirectUri         string                        `form:"redirect_uri"`
	Scope               string                        `form:"scope"`
	ResponseType        constants.ResponseType        `form:"response_type"`
	ResponseMode        constants.ResponseMode        `form:"response_mode,default=query"`
	State               string                        `form:"state"`
	CodeChallenge       string                        `form:"code_challenge"`
	CodeChallengeMethod constants.CodeChallengeMethod `form:"code_challenge_method"`
	RequestUri          string                        `form:"request_uri"`
	Nonce               string                        `form:"nonce"`
}

func (req BaseAuthorizeRequest) IsValid() error {

	// If the request URI is not passed, all the other mandatory parameters must be provided.
	if req.RequestUri == "" && unit.Any(
		[]string{req.RedirectUri, req.Scope, string(req.ResponseType)},
		func(s string) bool { return s == "" },
	) {
		return errors.New("invalid parameter")
	}

	// If the request URI is passed, all the other parameters must be empty.
	if req.RequestUri != "" && unit.Any(
		[]string{req.RedirectUri, req.Scope, string(req.ResponseType), string(req.ResponseMode), req.CodeChallenge, string(req.CodeChallengeMethod)},
		func(s string) bool { return s != "" },
	) {
		return errors.New("invalid parameter")
	}

	if req.ResponseType != "" && !slices.Contains(constants.ResponseTypes, req.ResponseType) {
		return errors.New("invalid response type")
	}

	if req.ResponseMode != "" && !slices.Contains(constants.ResponseModes, req.ResponseMode) {
		return errors.New("invalid response mode")
	}

	// Validate PKCE parameters.
	// The code challenge cannot be informed without the method and vice versa.
	if (req.CodeChallenge != "" && req.CodeChallengeMethod == "") || (req.CodeChallenge == "" && req.CodeChallengeMethod != "") {
		return errors.New("invalid parameters for PKCE")
	}

	return nil
}

type AuthorizeRequest struct {
	ClientId string `form:"client_id" binding:"required"`
	BaseAuthorizeRequest
}

type PARRequest struct {
	ClientAuthnRequest
	BaseAuthorizeRequest
}

func (req PARRequest) IsValid() error {

	if err := req.ClientAuthnRequest.IsValid(); err != nil {
		return err
	}

	if req.RequestUri != "" {
		return errors.New("invalid parameter")
	}
	return req.BaseAuthorizeRequest.IsValid()
}

type PARResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

type OpenIdConfiguration struct {
	Issuer                   string                            `json:"issuer"`
	AuthorizationEndpoint    string                            `json:"authorization_endpoint"`
	TokenEndpoint            string                            `json:"token_endpoint"`
	UserinfoEndpoint         string                            `json:"userinfo_endpoint"`
	JwksUri                  string                            `json:"jwks_uri"`
	ParEndpoint              string                            `json:"pushed_authorization_request_endpoint"`
	ResponseTypes            []constants.ResponseType          `json:"response_types_supported"`
	ResponseModes            []constants.ResponseMode          `json:"response_modes_supported"`
	GrantTypes               []constants.GrantType             `json:"grant_types_supported"`
	SubjectIdentifierTypes   []constants.SubjectIdentifierType `json:"subject_types_supported"`
	IdTokenSigningAlgorithms []jose.SignatureAlgorithm         `json:"id_token_signing_alg_values_supported"`
	ClientAuthnMethods       []constants.ClientAuthnType       `json:"token_endpoint_auth_methods_supported"`
}
