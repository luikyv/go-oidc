package authorize

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/timeutil"
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
			DPoPJWKThumbprint:   req.URL.Query().Get("dpop_jkt"),
			LoginHint:           req.URL.Query().Get("login_hint"),
			IDTokenHint:         req.URL.Query().Get("id_token_hint"),
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
			params.AuthDetails = authorizationDetailsObject
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
	errorCode         goidc.ErrorCode
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

func newFormRequest(req *http.Request) request {
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
		DPoPJWKThumbprint:   req.PostFormValue("dpop_jkt"),
		LoginHint:           req.PostFormValue("login_hint"),
		IDTokenHint:         req.PostFormValue("id_token_hint"),
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
			params.AuthDetails = authorizationDetailsObject
		}
	}

	return request{
		ClientID:                req.PostFormValue("client_id"),
		AuthorizationParameters: params,
	}
}

type pushedResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// TODO: Should ask the expiry?
func newAuthnSession(
	authParams goidc.AuthorizationParameters,
	client *goidc.Client,
) *goidc.AuthnSession {
	return &goidc.AuthnSession{
		ID:                       uuid.NewString(),
		ClientID:                 client.ID,
		AuthorizationParameters:  authParams,
		CreatedAtTimestamp:       timeutil.TimestampNow(),
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
		RedirectURI: nonZeroOrDefault(insideParams.RedirectURI,
			outsideParams.RedirectURI),
		ResponseMode: nonZeroOrDefault(insideParams.ResponseMode,
			outsideParams.ResponseMode),
		ResponseType: nonZeroOrDefault(insideParams.ResponseType,
			outsideParams.ResponseType),
		Scopes: nonZeroOrDefault(insideParams.Scopes,
			outsideParams.Scopes),
		State: nonZeroOrDefault(insideParams.State,
			outsideParams.State),
		Nonce: nonZeroOrDefault(insideParams.Nonce,
			outsideParams.Nonce),
		CodeChallenge: nonZeroOrDefault(insideParams.CodeChallenge,
			outsideParams.CodeChallenge),
		CodeChallengeMethod: nonZeroOrDefault(insideParams.CodeChallengeMethod,
			outsideParams.CodeChallengeMethod),
		Prompt: nonZeroOrDefault(insideParams.Prompt,
			outsideParams.Prompt),
		MaxAuthnAgeSecs: nonZeroOrDefault(insideParams.MaxAuthnAgeSecs,
			outsideParams.MaxAuthnAgeSecs),
		Display: nonZeroOrDefault(insideParams.Display,
			outsideParams.Display),
		ACRValues: nonZeroOrDefault(insideParams.ACRValues,
			outsideParams.ACRValues),
		Claims: nonZeroOrDefault(insideParams.Claims,
			outsideParams.Claims),
		AuthDetails: nonZeroOrDefault(insideParams.AuthDetails,
			outsideParams.AuthDetails),
		Resources: nonZeroOrDefault(insideParams.Resources,
			outsideParams.Resources),
		DPoPJWKThumbprint: nonZeroOrDefault(insideParams.DPoPJWKThumbprint,
			outsideParams.DPoPJWKThumbprint),
		LoginHint: nonZeroOrDefault(insideParams.LoginHint,
			outsideParams.LoginHint),
		IDTokenHint: nonZeroOrDefault(insideParams.IDTokenHint,
			outsideParams.IDTokenHint),
	}

	return params
}

func nonZeroOrDefault[T any](s1 T, s2 T) T {
	if isNil(s1) || reflect.ValueOf(s1).IsZero() {
		return s2
	}

	return s1
}

func isNil(i any) bool {
	return i == nil
}
