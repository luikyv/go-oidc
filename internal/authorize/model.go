package authorize

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type authorizationRequest struct {
	ClientID string `json:"client_id"`
	goidc.AuthorizationParameters
}

func newAuthorizationRequest(req *http.Request) authorizationRequest {
	params := authorizationRequest{
		ClientID: req.URL.Query().Get("client_id"),
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:          req.URL.Query().Get("request_uri"),
			RequestObject:       req.URL.Query().Get("request"),
			RedirectURI:         req.URL.Query().Get("redirect_uri"),
			ResponseMode:        goidc.ResponseMode(req.URL.Query().Get("response_mode")),
			ResponseType:        goidc.ResponseType(req.URL.Query().Get("response_type")),
			Scopes:              req.URL.Query().Get("scope"),
			State:               req.URL.Query().Get("state"),
			Nonce:               req.URL.Query().Get("nonce"),
			CodeChallenge:       req.URL.Query().Get("code_challenge"),
			CodeChallengeMethod: goidc.CodeChallengeMethod(req.URL.Query().Get("code_challenge_method")),
			Prompt:              goidc.PromptType(req.URL.Query().Get("prompt")),
			Display:             goidc.DisplayValue(req.URL.Query().Get("display")),
			ACRValues:           req.URL.Query().Get("acr_values"),
		},
	}

	maxAge, err := strconv.Atoi(req.URL.Query().Get("max_age"))
	if err == nil {
		params.MaxAuthnAgeSecs = &maxAge
	}

	claims := req.URL.Query().Get("claims")
	if claims != "" {
		var claimsObject goidc.ClaimsObject
		if err := json.Unmarshal([]byte(claims), &claimsObject); err == nil {
			params.Claims = &claimsObject
		}
	}

	authorizationDetails := req.URL.Query().Get("authorization_details")
	if authorizationDetails != "" {
		var authorizationDetailsObject []goidc.AuthorizationDetail
		if err := json.Unmarshal([]byte(authorizationDetails), &authorizationDetailsObject); err == nil {
			params.AuthorizationDetails = authorizationDetailsObject
		}
	}

	return params
}

type authorizationResponse struct {
	Response          string
	Issuer            string
	AccessToken       string
	TokenType         goidc.TokenType
	IDToken           string
	AuthorizationCode string
	State             string
	Error             oidc.ErrorCode
	ErrorDescription  string
}

func (rp authorizationResponse) Parameters() map[string]string {
	params := make(map[string]string)

	if rp.Response != "" {
		params["response"] = rp.Response
		return params
	}

	if rp.Issuer != "" {
		params["iss"] = rp.Issuer
	}
	if rp.AccessToken != "" {
		params["access_token"] = rp.AccessToken
	}
	if rp.TokenType != "" {
		params["token_type"] = string(rp.TokenType)
	}
	if rp.IDToken != "" {
		params["id_token"] = rp.IDToken
	}
	if rp.AuthorizationCode != "" {
		params["code"] = rp.AuthorizationCode
	}
	if rp.State != "" {
		params["state"] = rp.State
	}
	if rp.Error != "" {
		params["error"] = string(rp.Error)
	}
	if rp.ErrorDescription != "" {
		params["error_description"] = rp.ErrorDescription
	}

	return params
}

type pushedAuthorizationRequest struct {
	goidc.AuthorizationParameters
	client.AuthnRequest
}

func newPushedAuthorizationRequest(req *http.Request) pushedAuthorizationRequest {
	params := goidc.AuthorizationParameters{
		RequestURI:          req.PostFormValue("request_uri"),
		RequestObject:       req.PostFormValue("request"),
		RedirectURI:         req.PostFormValue("redirect_uri"),
		ResponseMode:        goidc.ResponseMode(req.PostFormValue("response_mode")),
		ResponseType:        goidc.ResponseType(req.PostFormValue("response_type")),
		Scopes:              req.PostFormValue("scope"),
		State:               req.PostFormValue("state"),
		Nonce:               req.PostFormValue("nonce"),
		CodeChallenge:       req.PostFormValue("code_challenge"),
		CodeChallengeMethod: goidc.CodeChallengeMethod(req.PostFormValue("code_challenge_method")),
		Prompt:              goidc.PromptType(req.PostFormValue("prompt")),
		Display:             goidc.DisplayValue(req.PostFormValue("display")),
		ACRValues:           req.PostFormValue("acr_values"),
	}

	maxAge, err := strconv.Atoi(req.PostFormValue("max_age"))
	if err == nil {
		params.MaxAuthnAgeSecs = &maxAge
	}

	claims := req.PostFormValue("claims")
	if claims != "" {
		var claimsObject goidc.ClaimsObject
		if err := json.Unmarshal([]byte(claims), &claimsObject); err == nil {
			params.Claims = &claimsObject
		}
	}

	authorizationDetails := req.PostFormValue("authorization_details")
	if authorizationDetails != "" {
		var authorizationDetailsObject []goidc.AuthorizationDetail
		if err := json.Unmarshal([]byte(authorizationDetails), &authorizationDetailsObject); err == nil {
			params.AuthorizationDetails = authorizationDetailsObject
		}
	}

	return pushedAuthorizationRequest{
		AuthnRequest:            client.NewAuthnRequest(req),
		AuthorizationParameters: params,
	}
}

type pushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

func newAuthnSession(authParams goidc.AuthorizationParameters, client *goidc.Client) *goidc.AuthnSession {
	return &goidc.AuthnSession{
		ID:                       uuid.NewString(),
		ClientID:                 client.ID,
		AuthorizationParameters:  authParams,
		CreatedAtTimestamp:       time.Now().Unix(),
		Store:                    make(map[string]any),
		AdditionalTokenClaims:    make(map[string]any),
		AdditionalIDTokenClaims:  map[string]any{},
		AdditionalUserInfoClaims: map[string]any{},
	}
}
