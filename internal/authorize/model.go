package authorize

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type request struct {
	ClientID string `json:"client_id"`
	goidc.AuthorizationParameters
}

func newRequest(req *http.Request) request {
	params := request{
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
			Resources:           req.URL.Query()["resource"],
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

type response struct {
	response          string
	issuer            string
	accessToken       string
	tokenType         goidc.TokenType
	idToken           string
	authorizationCode string
	state             string
	errorCode         oidc.ErrorCode
	errorDescription  string
}

func (resp response) parameters() map[string]string {
	params := make(map[string]string)

	if resp.response != "" {
		params["response"] = resp.response
		return params
	}

	if resp.issuer != "" {
		params["iss"] = resp.issuer
	}
	if resp.accessToken != "" {
		params["access_token"] = resp.accessToken
	}
	if resp.tokenType != "" {
		params["token_type"] = string(resp.tokenType)
	}
	if resp.idToken != "" {
		params["id_token"] = resp.idToken
	}
	if resp.authorizationCode != "" {
		params["code"] = resp.authorizationCode
	}
	if resp.state != "" {
		params["state"] = resp.state
	}
	if resp.errorCode != "" {
		params["error"] = string(resp.errorCode)
	}
	if resp.errorDescription != "" {
		params["error_description"] = resp.errorDescription
	}

	return params
}

type pushedRequest struct {
	goidc.AuthorizationParameters
	client.AuthnRequest
}

func newPushedRequest(req *http.Request) pushedRequest {
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
		Resources:           req.PostForm["resource"],
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

	return pushedRequest{
		AuthnRequest:            client.NewAuthnRequest(req),
		AuthorizationParameters: params,
	}
}

type pushedResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

func newAuthnSession(
	authParams goidc.AuthorizationParameters,
	client *goidc.Client,
) *goidc.AuthnSession {
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

func mergeParams(
	insideParams goidc.AuthorizationParameters,
	outsideParams goidc.AuthorizationParameters,
) goidc.AuthorizationParameters {
	params := goidc.AuthorizationParameters{
		RedirectURI: nonEmptyOrDefault(insideParams.RedirectURI,
			outsideParams.RedirectURI),
		ResponseMode: nonEmptyOrDefault(insideParams.ResponseMode,
			outsideParams.ResponseMode),
		ResponseType: nonEmptyOrDefault(insideParams.ResponseType,
			outsideParams.ResponseType),
		Scopes: nonEmptyOrDefault(insideParams.Scopes,
			outsideParams.Scopes),
		State: nonEmptyOrDefault(insideParams.State,
			outsideParams.State),
		Nonce: nonEmptyOrDefault(insideParams.Nonce,
			outsideParams.Nonce),
		CodeChallenge: nonEmptyOrDefault(insideParams.CodeChallenge,
			outsideParams.CodeChallenge),
		CodeChallengeMethod: nonEmptyOrDefault(insideParams.CodeChallengeMethod,
			outsideParams.CodeChallengeMethod),
		Prompt: nonEmptyOrDefault(insideParams.Prompt,
			outsideParams.Prompt),
		MaxAuthnAgeSecs: nonEmptyOrDefault(insideParams.MaxAuthnAgeSecs,
			outsideParams.MaxAuthnAgeSecs),
		Display: nonEmptyOrDefault(insideParams.Display,
			outsideParams.Display),
		ACRValues: nonEmptyOrDefault(insideParams.ACRValues,
			outsideParams.ACRValues),
		Claims: nonNilOrDefault(insideParams.Claims,
			outsideParams.Claims),
		AuthorizationDetails: nonNilOrDefault(insideParams.AuthorizationDetails,
			outsideParams.AuthorizationDetails),
	}

	return params
}

func nonEmptyOrDefault[T any](s1 T, s2 T) T {
	if reflect.ValueOf(s1).String() == "" {
		return s2
	}

	return s1
}

func nonNilOrDefault[T any](s1 T, s2 T) T {
	if reflect.ValueOf(s1).IsNil() {
		return s2
	}

	return s1
}
