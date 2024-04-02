package models

import (
	"errors"

	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type JWK struct {
	KeyId            string                     `json:"kid"`
	SigningAlgorithm constants.SigningAlgorithm `json:"alg"`
	KeyType          string                     `json:"kty"`
	Key              string                     `json:"k"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func (jwks JWKSet) GetKey(keyId string) JWK {
	jwk, _ := unit.FindFirst(jwks.Keys, func(jwk JWK) bool {
		return jwk.KeyId == keyId
	})

	return jwk
}

type TokenContextInfo struct {
	Subject  string
	ClientId string
	Scopes   []string
}

type Token struct {
	Id                 string
	TokenModelId       string
	TokenString        string
	RefreshToken       string
	ExpiresInSecs      int
	CreatedAtTimestamp int
	TokenContextInfo
}

type ClientAuthnRequest struct {
	ClientId     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret"`
}

type TokenRequest struct {
	ClientAuthnRequest
	GrantType         constants.GrantType `form:"grant_type" binding:"required"`
	Scope             string              `form:"scope"`
	AuthorizationCode string              `form:"code"`
	RedirectUri       string              `form:"redirect_uri"`
	RefreshToken      string              `form:"refresh_token"`
}

func (req TokenRequest) IsValid() error {
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
	RefreshToken string              `json:"refresh_token,omitempty"`
	ExpiresIn    int                 `json:"expires_in"`
	TokenType    constants.TokenType `json:"token_type"`
	Scope        string              `json:"scope,omitempty"`
}

type AuthorizeRequest struct {
	ClientId     string `form:"client_id" binding:"required"`
	RedirectUri  string `form:"redirect_uri"`
	Scope        string `form:"scope"`
	ResponseType string `form:"response_type"`
	State        string `form:"state"`
	RequestUri   string `form:"request_uri"`
}

func (req AuthorizeRequest) IsValid() error {
	if req.RequestUri == "" && (req.RedirectUri == "" || req.Scope == "" || req.ResponseType == "") {
		return errors.New("invalid parameter")
	}
	if req.RequestUri != "" && (req.RedirectUri != "" || req.Scope != "" || req.ResponseType != "") {
		return errors.New("invalid parameter")
	}
	return nil
}

type PARRequest struct {
	ClientAuthnRequest
	RedirectUri  string `form:"redirect_uri" binding:"required"`
	Scope        string `form:"scope" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
	State        string `form:"state"`
	RequestUri   string `form:"request_uri"` // It is here only to make sure the client doesn't pass it during the request.
}

func (req PARRequest) ToAuthorizeRequest() AuthorizeRequest {
	return AuthorizeRequest{
		ClientId:     req.ClientId,
		RedirectUri:  req.RedirectUri,
		Scope:        req.Scope,
		ResponseType: req.ResponseType,
		State:        req.State,
		RequestUri:   "", // Make sure the request URI is set as its null value here. This will force the authorize params to be validated.
	}
}

func (req PARRequest) IsValid() error {
	if req.RequestUri != "" {
		return errors.New("invalid parameter")
	}
	return req.ToAuthorizeRequest().IsValid()
}

type PARResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}
