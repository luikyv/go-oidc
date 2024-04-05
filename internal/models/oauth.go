package models

import (
	"errors"

	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type TokenContextInfo struct {
	Subject          string
	ClientId         string
	Scopes           []string
	GrantType        constants.GrantType
	AdditionalClaims map[string]string
}

func NewClientCredentialsGrantTokenContextInfoFromAuthnSession(client Client, req TokenRequest) TokenContextInfo {
	return TokenContextInfo{
		Subject:          client.Id,
		ClientId:         client.Id,
		Scopes:           unit.SplitStringWithSpaces(req.Scope),
		GrantType:        constants.ClientCredentials,
		AdditionalClaims: make(map[string]string),
	}
}

func NewAuthorizationCodeGrantTokenContextInfoFromAuthnSession(session AuthnSession) TokenContextInfo {
	return TokenContextInfo{
		Subject:          session.Subject,
		ClientId:         session.ClientId,
		Scopes:           session.Scopes,
		GrantType:        constants.AuthorizationCode,
		AdditionalClaims: session.AdditionalClaims,
	}
}

func NewRefreshTokenGrantTokenContextInfoFromAuthnSession(session TokenSession) TokenContextInfo {
	return TokenContextInfo{
		Subject:          session.Subject,
		ClientId:         session.ClientId,
		Scopes:           session.Scopes,
		GrantType:        constants.RefreshToken,
		AdditionalClaims: session.AdditionalClaims,
	}
}

type ClientAuthnRequest struct {
	ClientId            string                        `form:"client_id"`
	ClientSecret        string                        `form:"client_secret"`
	ClientAssertionType constants.ClientAssertionType `form:"client_assertion_type"`
	ClientAssertion     string                        `form:"client_assertion"`
}

func (req ClientAuthnRequest) IsValid() error {

	// Either the client ID or the client assertion must be present to identity the client.
	if req.ClientId == "" && req.ClientAssertion == "" {
		return errors.New("invalid authentication parameter")
	}

	// Validate parameters for client secret authentication.
	if req.ClientSecret != "" && (req.ClientAssertionType != "" || req.ClientAssertion != "") {
		return errors.New("invalid authentication parameter")
	}

	// Validate parameters for private key jwt authentication.
	if req.ClientAssertion != "" && (req.ClientAssertionType != constants.JWTBearerAssertion || req.ClientSecret != "") {
		return errors.New("invalid authentication parameter")
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
		if req.RefreshToken == "" || req.AuthorizationCode != "" || req.RedirectUri != "" {
			return errors.New("invalid parameter for refresh token grant")
		}
	default:
		return errors.New("invalid grant type")
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
	ResponseType        string                        `form:"response_type"`
	State               string                        `form:"state"`
	CodeChallenge       string                        `form:"code_challenge"`
	CodeChallengeMethod constants.CodeChallengeMethod `form:"code_challenge_method"`
	RequestUri          string                        `form:"request_uri"`
}

type AuthorizeRequest struct {
	ClientId string `form:"client_id" binding:"required"`
	BaseAuthorizeRequest
}

func (req AuthorizeRequest) IsValid() error {

	// If the request URI is not passed, all the other parameters must be provided.
	if req.RequestUri == "" && (req.RedirectUri == "" || req.Scope == "" || req.ResponseType == "") {
		return errors.New("invalid parameter")
	}

	// If the request URI is passed, all the other parameters must be empty.
	if req.RequestUri != "" && (req.RedirectUri != "" || req.Scope != "" || req.ResponseType != "") {
		return errors.New("invalid parameter")
	}

	// Validate PKCE parameters.
	if (req.CodeChallenge != "" && req.CodeChallengeMethod == "") || (req.CodeChallenge == "" && req.CodeChallengeMethod != "") {
		return errors.New("invalid parameters for PKCE")
	}

	return nil
}

type PARRequest struct {
	ClientAuthnRequest
	BaseAuthorizeRequest
}

func (req PARRequest) ToAuthorizeRequest() AuthorizeRequest {
	return AuthorizeRequest{
		ClientId:             req.ClientId,
		BaseAuthorizeRequest: req.BaseAuthorizeRequest,
	}
}

func (req PARRequest) IsValid() error {

	if req.RequestUri != "" {
		return errors.New("invalid parameter")
	}

	if err := req.ClientAuthnRequest.IsValid(); err != nil {
		return err
	}

	return req.ToAuthorizeRequest().IsValid()
}

type PARResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}
