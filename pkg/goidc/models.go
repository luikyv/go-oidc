package goidc

import (
	"crypto/x509"
	"html/template"
	"maps"
)

type Context interface {
	GetHost() string
	GetHeader(header string) (string, bool)
	GetFormParam(param string) string
	GetSecureClientCertificate() (*x509.Certificate, bool)
	GetClientCertificate() (*x509.Certificate, bool)
	RenderHtml(html string, params any)
	RenderHtmlTemplate(tmpl *template.Template, params any)
}

type AuthnSession interface {
	SetUserId(userId string)
	// Get the ID associate to the current user interaction.
	GetCallbackId() string
	// Get the scopes requested by the client.
	GetScopes() string
	GetPromptType() (PromptType, bool)
	GetMaxAuthenticationAgeSecs() (int, bool)
	GetDisplayValue() (DisplayValue, bool)
	GetAcrValues() ([]AuthenticationContextReference, bool)
	GetAuthorizationDetails() (details []AuthorizationDetail, ok bool)
	// Get the claims requested by the client using the claims parameter.
	GetClaims() (claims ClaimsObject, ok bool)
	// Save a paramater in the session so it can be used across steps.
	SaveParameter(key string, value any)
	// Get a parameter saved in the session.
	GetParameter(key string) (value any, ok bool)
	// Set a new claim that will be mapped in the access token when issued.
	AddTokenClaim(claim string, value any)
	// Set a new claim that will be mapped in the ID token when issued.
	AddIdTokenClaim(claim string, value any)
	// Set a new claim that will be mapped in the user info endpoint.
	AddUserInfoClaim(claim string, value any)
	// Set the scopes the client will have access to use.
	GrantScopes(scopes string)
	GrantAuthorizationDetails(authDetails []AuthorizationDetail)
	// Get custom protected parameters sent during PAR or JAR.
	// TODO: Explain this.
	GetProtectedParameter(key string) (value any, ok bool)
	// Define the error that will be redirected to the client.
	// This only has effect when a failure status is returned by the authentication policy.
	SetRedirectError(errorCode ErrorCode, errorDescription string)
}

type Client interface {
	GetId() string
	// Get the value of a custom attribute.
	GetAttribute(key string) (any, bool)
	GetName() (string, bool)
}

type DynamicClient interface {
	// Set a custom attribute.
	SetAttribute(key string, value any)
}

type DcrPluginFunc func(ctx Context, dynamicClient DynamicClient)

type AuthnFunc func(Context, AuthnSession) AuthnStatus

type SetUpPolicyFunc func(ctx Context, client Client, session AuthnSession) (selected bool)

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
	tokenLifetimeSecs int,
	signatureKeyId string,
	shouldRefresh bool,
) TokenOptions {
	return TokenOptions{
		TokenFormat:        OpaqueTokenFormat,
		TokenExpiresInSecs: tokenLifetimeSecs,
		JwtSignatureKeyId:  signatureKeyId,
		ShouldRefresh:      shouldRefresh,
	}
}

func NewOpaqueTokenOptions(
	tokenLifetimeSecs int,
	tokenLength int,
) TokenOptions {
	return TokenOptions{
		TokenFormat:        JwtTokenFormat,
		TokenExpiresInSecs: tokenLifetimeSecs,
		OpaqueTokenLength:  tokenLength,
	}
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
