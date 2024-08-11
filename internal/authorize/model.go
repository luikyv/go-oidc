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

type Request struct {
	ClientID string `json:"client_id"`
	goidc.AuthorizationParameters
}

func newRequest(req *http.Request) Request {
	params := Request{
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

	if maxAge, err := strconv.Atoi(req.URL.Query().Get("max_age")); err == nil {
		params.MaxAuthnAgeSecs = &maxAge
	}

	if claims := req.URL.Query().Get("claims"); claims != "" {
		var claimsObject goidc.ClaimsObject
		if err := json.Unmarshal([]byte(claims), &claimsObject); err == nil {
			params.Claims = &claimsObject
		}
	}

	if authorizationDetails := req.URL.Query().Get("authorization_details"); authorizationDetails != "" {
		var authorizationDetailsObject []goidc.AuthorizationDetail
		if err := json.Unmarshal([]byte(authorizationDetails), &authorizationDetailsObject); err == nil {
			params.AuthorizationDetails = authorizationDetailsObject
		}
	}

	return params
}

type Response struct {
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

func (resp Response) parameters() map[string]string {
	params := make(map[string]string)

	if resp.Response != "" {
		params["response"] = resp.Response
		return params
	}

	if resp.Issuer != "" {
		params["iss"] = resp.Issuer
	}
	if resp.AccessToken != "" {
		params["access_token"] = resp.AccessToken
	}
	if resp.TokenType != "" {
		params["token_type"] = string(resp.TokenType)
	}
	if resp.IDToken != "" {
		params["id_token"] = resp.IDToken
	}
	if resp.AuthorizationCode != "" {
		params["code"] = resp.AuthorizationCode
	}
	if resp.State != "" {
		params["state"] = resp.State
	}
	if resp.Error != "" {
		params["error"] = string(resp.Error)
	}
	if resp.ErrorDescription != "" {
		params["error_description"] = resp.ErrorDescription
	}

	return params
}

type PushedRequest struct {
	goidc.AuthorizationParameters
	client.AuthnRequest
}

func newPushedRequest(req *http.Request) PushedRequest {
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

	if maxAge, err := strconv.Atoi(req.PostFormValue("max_age")); err == nil {
		params.MaxAuthnAgeSecs = &maxAge
	}

	if claims := req.PostFormValue("claims"); claims != "" {
		var claimsObject goidc.ClaimsObject
		if err := json.Unmarshal([]byte(claims), &claimsObject); err == nil {
			params.Claims = &claimsObject
		}
	}

	if authorizationDetails := req.PostFormValue("authorization_details"); authorizationDetails != "" {
		var authorizationDetailsObject []goidc.AuthorizationDetail
		if err := json.Unmarshal([]byte(authorizationDetails), &authorizationDetailsObject); err == nil {
			params.AuthorizationDetails = authorizationDetailsObject
		}
	}

	return PushedRequest{
		AuthnRequest:            client.NewAuthnRequest(req),
		AuthorizationParameters: params,
	}
}

type PushedResponse struct {
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
