package authorize

import (
	"encoding/json"
	"fmt"
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

// UnmarshalJSON makes sure the field "requested_expiry" can be unmarshalled
// either from an integer or an string.
func (req *request) UnmarshalJSON(data []byte) error {
	type alias request
	aux := &struct {
		RequestedExpiry json.RawMessage `json:"requested_expiry"`
		*alias
	}{
		alias: (*alias)(req),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.RequestedExpiry == nil {
		return nil
	}

	var intValue int
	if err := json.Unmarshal(aux.RequestedExpiry, &intValue); err == nil {
		req.RequestedExpiry = &intValue
		return nil
	}

	var strValue string
	if err := json.Unmarshal(aux.RequestedExpiry, &strValue); err != nil {
		return fmt.Errorf("requested_expiry is neither int nor string: %w", err)
	}

	intValue, err := strconv.Atoi(strValue)
	if err != nil {
		return fmt.Errorf("requested_expiry is an invalid integer string: %w", err)
	}
	req.RequestedExpiry = &intValue
	return nil
}

func newRequest(req *http.Request) request {
	params := request{
		ClientID: req.URL.Query().Get("client_id"),
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:              req.URL.Query().Get("request_uri"),
			RequestObject:           req.URL.Query().Get("request"),
			RedirectURI:             req.URL.Query().Get("redirect_uri"),
			ResponseMode:            goidc.ResponseMode(req.URL.Query().Get("response_mode")),
			ResponseType:            goidc.ResponseType(req.URL.Query().Get("response_type")),
			Scopes:                  req.URL.Query().Get("scope"),
			State:                   req.URL.Query().Get("state"),
			Nonce:                   req.URL.Query().Get("nonce"),
			CodeChallenge:           req.URL.Query().Get("code_challenge"),
			CodeChallengeMethod:     goidc.CodeChallengeMethod(req.URL.Query().Get("code_challenge_method")),
			Prompt:                  goidc.PromptType(req.URL.Query().Get("prompt")),
			Display:                 goidc.DisplayValue(req.URL.Query().Get("display")),
			ACRValues:               req.URL.Query().Get("acr_values"),
			Resources:               req.URL.Query()["resource"],
			DPoPJKT:                 req.URL.Query().Get("dpop_jkt"),
			LoginHint:               req.URL.Query().Get("login_hint"),
			LoginTokenHint:          req.URL.Query().Get("login_token_hint"),
			IDTokenHint:             req.URL.Query().Get("id_token_hint"),
			ClientNotificationToken: req.URL.Query().Get("client_notification_token"),
			BindingMessage:          req.URL.Query().Get("binding_message"),
			UserCode:                req.URL.Query().Get("user_code"),
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

	if requestedExpiry, err := strconv.Atoi(req.URL.Query().Get("requested_expiry")); err == nil {
		params.RequestedExpiry = &requestedExpiry
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
	errorURI          string
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
	if resp.errorURI != "" {
		params["error_uri"] = resp.errorURI
	}

	return params
}

func newFormRequest(req *http.Request) request {
	params := goidc.AuthorizationParameters{
		RequestURI:              req.PostFormValue("request_uri"),
		RequestObject:           req.PostFormValue("request"),
		RedirectURI:             req.PostFormValue("redirect_uri"),
		ResponseMode:            goidc.ResponseMode(req.PostFormValue("response_mode")),
		ResponseType:            goidc.ResponseType(req.PostFormValue("response_type")),
		Scopes:                  req.PostFormValue("scope"),
		State:                   req.PostFormValue("state"),
		Nonce:                   req.PostFormValue("nonce"),
		CodeChallenge:           req.PostFormValue("code_challenge"),
		CodeChallengeMethod:     goidc.CodeChallengeMethod(req.PostFormValue("code_challenge_method")),
		Prompt:                  goidc.PromptType(req.PostFormValue("prompt")),
		Display:                 goidc.DisplayValue(req.PostFormValue("display")),
		ACRValues:               req.PostFormValue("acr_values"),
		Resources:               req.PostForm["resource"],
		DPoPJKT:                 req.PostFormValue("dpop_jkt"),
		LoginHint:               req.PostFormValue("login_hint"),
		LoginTokenHint:          req.PostFormValue("login_hint_token"),
		IDTokenHint:             req.PostFormValue("id_token_hint"),
		ClientNotificationToken: req.PostFormValue("client_notification_token"),
		BindingMessage:          req.PostFormValue("binding_message"),
		UserCode:                req.PostFormValue("user_code"),
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

	if requestedExpiry, err := strconv.Atoi(req.PostFormValue("requested_expiry")); err == nil {
		params.RequestedExpiry = &requestedExpiry
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

type cibaResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// TODO: Should ask the expiry?
func newAuthnSession(authParams goidc.AuthorizationParameters, client *goidc.Client) *goidc.AuthnSession {
	return &goidc.AuthnSession{
		ID:                       uuid.NewString(),
		ClientID:                 client.ID,
		AuthorizationParameters:  authParams,
		CreatedAtTimestamp:       timeutil.TimestampNow(),
		Storage:                  make(map[string]any),
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
		DPoPJKT: nonZeroOrDefault(insideParams.DPoPJKT,
			outsideParams.DPoPJKT),
		LoginHint: nonZeroOrDefault(insideParams.LoginHint,
			outsideParams.LoginHint),
		LoginTokenHint: nonZeroOrDefault(insideParams.LoginTokenHint,
			outsideParams.LoginTokenHint),
		IDTokenHint: nonZeroOrDefault(insideParams.IDTokenHint,
			outsideParams.IDTokenHint),
		ClientNotificationToken: nonZeroOrDefault(insideParams.ClientNotificationToken,
			outsideParams.ClientNotificationToken),
		BindingMessage: nonZeroOrDefault(insideParams.BindingMessage,
			outsideParams.BindingMessage),
		UserCode: nonZeroOrDefault(insideParams.UserCode,
			outsideParams.UserCode),
		RequestedExpiry: nonZeroOrDefault(insideParams.RequestedExpiry,
			outsideParams.RequestedExpiry),
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
