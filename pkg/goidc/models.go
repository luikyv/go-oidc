package goidc

import (
	"maps"
	"reflect"
)

// Function responsible for executing the user authentication logic.
type AuthnFunc func(Context, *AuthnSession) AuthnStatus

// Function responsible for deciding if the corresponding policy will be executed.
// It can be used to initialize the session as well.
type SetUpPolicyFunc func(ctx Context, client Client, session *AuthnSession) (selected bool)

type AuthnPolicy struct {
	Id        string
	AuthnFunc AuthnFunc
	SetUpFunc SetUpPolicyFunc
}

// Create a policy that will be selected based on setUpFunc and that authenticates users with authnFunc.
func NewPolicy(
	id string,
	setUpFunc SetUpPolicyFunc,
	authnFunc AuthnFunc,
) AuthnPolicy {
	return AuthnPolicy{
		Id:        id,
		AuthnFunc: authnFunc,
		SetUpFunc: setUpFunc,
	}
}

type GrantOptions struct {
	GrantType                   GrantType             `json:"grant_type"`
	Subject                     string                `json:"sub"`
	ClientId                    string                `json:"client_id"`
	GrantedScopes               string                `json:"scopes"`
	GrantedAuthorizationDetails []AuthorizationDetail `json:"authorization_details"`
	CreatedAtTimestamp          int                   `json:"created_at"`
	AdditionalIdTokenClaims     map[string]any        `json:"additional_id_token_claims"`
	AdditionalUserInfoClaims    map[string]any        `json:"additional_user_info_claims"`
	TokenOptions
}

type GetTokenOptionsFunc func(client Client, scopes string) (TokenOptions, error)

type TokenOptions struct {
	TokenFormat           TokenFormat    `json:"token_format"`
	TokenExpiresInSecs    int            `json:"token_expires_in_secs"`
	ShouldRefresh         bool           `json:"is_refreshable"`
	JwtSignatureKeyId     string         `json:"token_signature_key_id"`
	OpaqueTokenLength     int            `json:"opaque_token_length"`
	AdditionalTokenClaims map[string]any `json:"additional_token_claims"`
}

func (opts *TokenOptions) AddTokenClaims(claims map[string]any) {
	if opts.AdditionalTokenClaims == nil {
		opts.AdditionalTokenClaims = map[string]any{}
	}
	maps.Copy(opts.AdditionalTokenClaims, claims)
}

func NewJwtTokenOptions(
	// The ID of a signing key present in the server JWKS.
	signatureKeyId string,
	tokenLifetimeSecs int,
	shouldRefresh bool,
) TokenOptions {
	return TokenOptions{
		TokenFormat:        JwtTokenFormat,
		TokenExpiresInSecs: tokenLifetimeSecs,
		JwtSignatureKeyId:  signatureKeyId,
		ShouldRefresh:      shouldRefresh,
	}
}

func NewOpaqueTokenOptions(
	tokenLength int,
	tokenLifetimeSecs int,
	shouldRefresh bool,
) TokenOptions {
	return TokenOptions{
		TokenFormat:        OpaqueTokenFormat,
		TokenExpiresInSecs: tokenLifetimeSecs,
		OpaqueTokenLength:  tokenLength,
		ShouldRefresh:      shouldRefresh,
	}
}

type AuthorizationParameters struct {
	RequestUri          string              `json:"request_uri,omitempty" bson:"request_uri,omitempty"`
	RequestObject       string              `json:"request,omitempty" bson:"request,omitempty"`
	RedirectUri         string              `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	ResponseMode        ResponseMode        `json:"response_mode,omitempty" bson:"response_mode,omitempty"`
	ResponseType        ResponseType        `json:"response_type,omitempty" bson:"response_type,omitempty"`
	Scopes              string              `json:"scope,omitempty" bson:"scope,omitempty"`
	State               string              `json:"state,omitempty" bson:"state,omitempty"`
	Nonce               string              `json:"nonce,omitempty" bson:"nonce,omitempty"`
	CodeChallenge       string              `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method,omitempty" bson:"code_challenge_method,omitempty"`
	Prompt              PromptType          `json:"prompt,omitempty" bson:"prompt,omitempty"`
	// MaxAuthenticationAgeSecs is a pointer to help differentiate when it's null or not.
	MaxAuthenticationAgeSecs *int         `json:"max_age,omitempty" bson:"max_age,omitempty"`
	Display                  DisplayValue `json:"display,omitempty" bson:"display,omitempty"`
	AcrValues                string       `json:"acr_values,omitempty" bson:"acr_values,omitempty"`
	// Claims is a pointer to help differentiate when it's null or not.
	Claims               *ClaimsObject         `json:"claims,omitempty" bson:"claims,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty" bson:"authorization_details,omitempty"`
}

func (insideParams AuthorizationParameters) Merge(outsideParams AuthorizationParameters) AuthorizationParameters {
	params := AuthorizationParameters{
		RedirectUri:              getNonEmptyOrDefault(insideParams.RedirectUri, outsideParams.RedirectUri),
		ResponseMode:             getNonEmptyOrDefault(insideParams.ResponseMode, outsideParams.ResponseMode),
		ResponseType:             getNonEmptyOrDefault(insideParams.ResponseType, outsideParams.ResponseType),
		Scopes:                   getNonEmptyOrDefault(insideParams.Scopes, outsideParams.Scopes),
		State:                    getNonEmptyOrDefault(insideParams.State, outsideParams.State),
		Nonce:                    getNonEmptyOrDefault(insideParams.Nonce, outsideParams.Nonce),
		CodeChallenge:            getNonEmptyOrDefault(insideParams.CodeChallenge, outsideParams.CodeChallenge),
		CodeChallengeMethod:      getNonEmptyOrDefault(insideParams.CodeChallengeMethod, outsideParams.CodeChallengeMethod),
		Prompt:                   getNonEmptyOrDefault(insideParams.Prompt, outsideParams.Prompt),
		MaxAuthenticationAgeSecs: getNonEmptyOrDefault(insideParams.MaxAuthenticationAgeSecs, outsideParams.MaxAuthenticationAgeSecs),
		Display:                  getNonEmptyOrDefault(insideParams.Display, outsideParams.Display),
		AcrValues:                getNonEmptyOrDefault(insideParams.AcrValues, outsideParams.AcrValues),
		Claims:                   getNonNilOrDefault(insideParams.Claims, outsideParams.Claims),
		AuthorizationDetails:     getNonNilOrDefault(insideParams.AuthorizationDetails, outsideParams.AuthorizationDetails),
	}

	return params
}

func (params AuthorizationParameters) NewRedirectError(
	errorCode ErrorCode,
	errorDescription string,
) OAuthRedirectError {
	return OAuthRedirectError{
		OAuthBaseError: OAuthBaseError{
			ErrorCode:        errorCode,
			ErrorDescription: errorDescription,
		},
		AuthorizationParameters: params,
	}
}

// Get the response mode based on the response type.
func (params AuthorizationParameters) GetResponseMode() ResponseMode {
	if params.ResponseMode == "" {
		return params.ResponseType.GetDefaultResponseMode(false)
	}

	if params.ResponseMode == JwtResponseMode {
		return params.ResponseType.GetDefaultResponseMode(true)
	}

	return params.ResponseMode
}

type ClaimsObject struct {
	Userinfo map[string]ClaimObjectInfo `json:"userinfo"`
	IdToken  map[string]ClaimObjectInfo `json:"id_token"`
}

// TODO: add functions to the claims object.

type ClaimObjectInfo struct {
	IsEssential bool     `json:"essential"`
	Value       string   `json:"value"`
	Values      []string `json:"values"`
}

// Authorization details is a map instead of a struct, because its fields vary a lot depending on the use case.
// Some fields are well know so they are accessible as methods.
type AuthorizationDetail map[string]any

func (detail AuthorizationDetail) GetType() string {
	return detail.getString("type")
}

func (detail AuthorizationDetail) GetIdentifier() string {
	return detail.getString("identifier")
}

func (detail AuthorizationDetail) GetLocations() []string {
	return detail.getStringSlice("locations")
}

func (detail AuthorizationDetail) GetActions() []string {
	return detail.getStringSlice("actions")
}

func (detail AuthorizationDetail) GetDataTypes() []string {
	return detail.getStringSlice("datatypes")
}

func (detail AuthorizationDetail) getStringSlice(key string) []string {
	value, ok := detail[key]
	if !ok {
		return nil
	}

	slice, ok := value.([]string)
	if !ok {
		return nil
	}

	return slice
}

func (detail AuthorizationDetail) getString(key string) string {
	value, ok := detail[key]
	if !ok {
		return ""
	}

	s, ok := value.(string)
	if !ok {
		return ""
	}

	return s
}

func getNonEmptyOrDefault[T any](s1 T, s2 T) T {
	if reflect.ValueOf(s1).String() == "" {
		return s2
	}

	return s1
}

func getNonNilOrDefault[T any](s1 T, s2 T) T {
	if reflect.ValueOf(s1).IsNil() {
		return s2
	}

	return s1
}
