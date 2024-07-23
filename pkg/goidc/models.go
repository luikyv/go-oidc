package goidc

import (
	"encoding/json"
	"maps"
	"reflect"
)

type AuthorizeErrorPluginFunc func(ctx Context, err OAuthError) error

// AuthnFunc executes the user authentication logic.
type AuthnFunc func(Context, *AuthnSession) AuthnStatus

// SetUpAuthnFunc is responsible for deciding if the corresponding policy will be executed.
type SetUpAuthnFunc func(Context, *Client, *AuthnSession) bool

type AuthnPolicy struct {
	ID           string
	SetUp        SetUpAuthnFunc
	Authenticate AuthnFunc
}

// NewPolicy creates a policy that will be selected based on setUpFunc and that authenticates users with authnFunc.
func NewPolicy(
	id string,
	setUpFunc SetUpAuthnFunc,
	authnFunc AuthnFunc,
) AuthnPolicy {
	return AuthnPolicy{
		ID:           id,
		Authenticate: authnFunc,
		SetUp:        setUpFunc,
	}
}

type UserInfo struct {
	UserID         string
	AuthnTimestamp int
	AuthnContext   AuthenticationContextReference
	AuthnMethods   []AuthenticationMethodReference
}

type GrantOptions struct {
	GrantType                   GrantType             `json:"grant_type" bson:"grant_type"`
	Subject                     string                `json:"sub" bson:"sub"`
	ClientID                    string                `json:"client_id" bson:"client_id"`
	GrantedScopes               string                `json:"granted_scopes" bson:"granted_scopes"`
	GrantedAuthorizationDetails []AuthorizationDetail `json:"granted_authorization_details,omitempty" bson:"granted_authorization_details,omitempty"`
	AdditionalIDTokenClaims     map[string]any        `json:"additional_id_token_claims,omitempty" bson:"additional_id_token_claims,omitempty"`
	AdditionalUserInfoClaims    map[string]any        `json:"additional_user_info_claims,omitempty" bson:"additional_user_info_claims,omitempty"`
	TokenOptions                `bson:"inline"`
}

type TokenOptionsFunc func(client *Client, scopes string) (TokenOptions, error)

// TODO: Allow passing the token ID? Or a prefix?
type TokenOptions struct {
	TokenFormat           TokenFormat    `json:"token_format" bson:"token_format"`
	TokenLifetimeSecs     int            `json:"token_lifetime_secs" bson:"token_lifetime_secs"`
	JWTSignatureKeyID     string         `json:"token_signature_key_id,omitempty" bson:"token_signature_key_id,omitempty"`
	OpaqueTokenLength     int            `json:"opaque_token_length,omitempty" bson:"opaque_token_length,omitempty"`
	AdditionalTokenClaims map[string]any `json:"additional_token_claims,omitempty" bson:"additional_token_claims,omitempty"`
}

func (opts *TokenOptions) AddTokenClaims(claims map[string]any) {
	if opts.AdditionalTokenClaims == nil {
		opts.AdditionalTokenClaims = map[string]any{}
	}
	maps.Copy(opts.AdditionalTokenClaims, claims)
}

func NewJWTTokenOptions(
	// signatureKeyID is the ID of a signing key present in the server JWKS.
	signatureKeyID string,
	tokenLifetimeSecs int,
) TokenOptions {
	return TokenOptions{
		TokenFormat:       TokenFormatJWT,
		TokenLifetimeSecs: tokenLifetimeSecs,
		JWTSignatureKeyID: signatureKeyID,
	}
}

func NewOpaqueTokenOptions(
	tokenLength int,
	tokenLifetimeSecs int,
) TokenOptions {
	return TokenOptions{
		TokenFormat:       TokenFormatOpaque,
		TokenLifetimeSecs: tokenLifetimeSecs,
		OpaqueTokenLength: tokenLength,
	}
}

type AuthorizationParameters struct {
	RequestURI           string                `json:"request_uri,omitempty" bson:"request_uri,omitempty"`
	RequestObject        string                `json:"request,omitempty" bson:"request,omitempty"`
	RedirectURI          string                `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	ResponseMode         ResponseMode          `json:"response_mode,omitempty" bson:"response_mode,omitempty"`
	ResponseType         ResponseType          `json:"response_type,omitempty" bson:"response_type,omitempty"`
	Scopes               string                `json:"scope,omitempty" bson:"scope,omitempty"`
	State                string                `json:"state,omitempty" bson:"state,omitempty"`
	Nonce                string                `json:"nonce,omitempty" bson:"nonce,omitempty"`
	CodeChallenge        string                `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`
	CodeChallengeMethod  CodeChallengeMethod   `json:"code_challenge_method,omitempty" bson:"code_challenge_method,omitempty"`
	Prompt               PromptType            `json:"prompt,omitempty" bson:"prompt,omitempty"`
	MaxAuthnAgeSecs      *int                  `json:"max_age,omitempty" bson:"max_age,omitempty"`
	Display              DisplayValue          `json:"display,omitempty" bson:"display,omitempty"`
	ACRValues            string                `json:"acr_values,omitempty" bson:"acr_values,omitempty"`
	Claims               *ClaimsObject         `json:"claims,omitempty" bson:"claims,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty" bson:"authorization_details,omitempty"`
}

func (insideParams AuthorizationParameters) Merge(outsideParams AuthorizationParameters) AuthorizationParameters {
	params := AuthorizationParameters{
		RedirectURI:          nonEmptyOrDefault(insideParams.RedirectURI, outsideParams.RedirectURI),
		ResponseMode:         nonEmptyOrDefault(insideParams.ResponseMode, outsideParams.ResponseMode),
		ResponseType:         nonEmptyOrDefault(insideParams.ResponseType, outsideParams.ResponseType),
		Scopes:               nonEmptyOrDefault(insideParams.Scopes, outsideParams.Scopes),
		State:                nonEmptyOrDefault(insideParams.State, outsideParams.State),
		Nonce:                nonEmptyOrDefault(insideParams.Nonce, outsideParams.Nonce),
		CodeChallenge:        nonEmptyOrDefault(insideParams.CodeChallenge, outsideParams.CodeChallenge),
		CodeChallengeMethod:  nonEmptyOrDefault(insideParams.CodeChallengeMethod, outsideParams.CodeChallengeMethod),
		Prompt:               nonEmptyOrDefault(insideParams.Prompt, outsideParams.Prompt),
		MaxAuthnAgeSecs:      nonEmptyOrDefault(insideParams.MaxAuthnAgeSecs, outsideParams.MaxAuthnAgeSecs),
		Display:              nonEmptyOrDefault(insideParams.Display, outsideParams.Display),
		ACRValues:            nonEmptyOrDefault(insideParams.ACRValues, outsideParams.ACRValues),
		Claims:               nonNilOrDefault(insideParams.Claims, outsideParams.Claims),
		AuthorizationDetails: nonNilOrDefault(insideParams.AuthorizationDetails, outsideParams.AuthorizationDetails),
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

// DefaultResponseMode returns the response mode based on the response type.
func (params AuthorizationParameters) DefaultResponseMode() ResponseMode {
	if params.ResponseMode == "" {
		return params.ResponseType.DefaultResponseMode(false)
	}

	if params.ResponseMode == ResponseModeJWT {
		return params.ResponseType.DefaultResponseMode(true)
	}

	return params.ResponseMode
}

type TokenIntrospectionInfo struct {
	IsActive                    bool
	TokenUsage                  TokenTypeHint
	Scopes                      string
	AuthorizationDetails        []AuthorizationDetail
	ClientID                    string
	Subject                     string
	ExpiresAtTimestamp          int
	JWKThumbprint               string
	ClientCertificateThumbprint string
	AdditionalTokenClaims       map[string]any
}

func (info TokenIntrospectionInfo) MarshalJSON() ([]byte, error) {
	if !info.IsActive {
		return json.Marshal(map[string]any{
			"active": false,
		})
	}

	params := map[string]any{
		"active":      true,
		"token_usage": info.TokenUsage,
		ClaimSubject:  info.Subject,
		ClaimScope:    info.Scopes,
		ClaimClientID: info.ClientID,
		ClaimExpiry:   info.ExpiresAtTimestamp,
	}

	if info.AuthorizationDetails != nil {
		params[ClaimAuthorizationDetails] = info.AuthorizationDetails
	}

	confirmation := make(map[string]string)
	if info.JWKThumbprint != "" {
		confirmation["jkt"] = info.JWKThumbprint
	}
	if info.ClientCertificateThumbprint != "" {
		confirmation["x5t#S256"] = info.ClientCertificateThumbprint
	}
	if len(confirmation) != 0 {
		params["cnf"] = confirmation
	}

	for k, v := range info.AdditionalTokenClaims {
		params[k] = v
	}

	return json.Marshal(params)
}

type ClaimsObject struct {
	UserInfo map[string]ClaimObjectInfo `json:"userinfo"`
	IDToken  map[string]ClaimObjectInfo `json:"id_token"`
}

// UserInfoEssentials returns all the essentials claims requested by the client to be returned in the userinfo endpoint.
func (claims ClaimsObject) UserInfoEssentials() []string {
	return essentials(claims.UserInfo)
}

// UserInfoEssentials returns all the essentials claims requested by the client to be returned in the ID token.
func (claims ClaimsObject) IDTokenEssentials() []string {
	return essentials(claims.IDToken)
}

// UserInfoEssentials returns the claim object info if present.
func (claims ClaimsObject) UserInfoClaim(claimName string) (ClaimObjectInfo, bool) {
	return claim(claimName, claims.UserInfo)
}

// IDTokenClaim returns the claim object info if present.
func (claims ClaimsObject) IDTokenClaim(claimName string) (ClaimObjectInfo, bool) {
	return claim(claimName, claims.IDToken)
}

func claim(claim string, claims map[string]ClaimObjectInfo) (ClaimObjectInfo, bool) {
	for name, claimInfo := range claims {
		if name == claim {
			return claimInfo, true
		}
	}
	return ClaimObjectInfo{}, false
}

func essentials(claims map[string]ClaimObjectInfo) []string {
	var essentialClaims []string
	for name, claim := range claims {
		if claim.IsEssential {
			essentialClaims = append(essentialClaims, name)
		}
	}
	return essentialClaims
}

type ClaimObjectInfo struct {
	IsEssential bool     `json:"essential"`
	Value       string   `json:"value"`
	Values      []string `json:"values"`
}

// Authorization details is a map instead of a struct, because its fields vary a lot depending on the use case.
// Some fields are well know so they are accessible as methods.
type AuthorizationDetail map[string]any

func (detail AuthorizationDetail) Type() string {
	return detail.string("type")
}

func (detail AuthorizationDetail) Identifier() string {
	return detail.string("identifier")
}

func (detail AuthorizationDetail) Locations() []string {
	return detail.stringSlice("locations")
}

func (detail AuthorizationDetail) Actions() []string {
	return detail.stringSlice("actions")
}

func (detail AuthorizationDetail) DataTypes() []string {
	return detail.stringSlice("datatypes")
}

func (detail AuthorizationDetail) stringSlice(key string) []string {
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

func (detail AuthorizationDetail) string(key string) string {
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
