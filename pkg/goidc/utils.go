package goidc

import (
	"crypto/x509"
	"html/template"
	"maps"

	"github.com/go-jose/go-jose/v4"
)

type Context interface {
	GetHost() string
	GetHeader(header string) (headerValue string, ok bool)
	GetFormParam(param string) (formValue string)
	GetSecureClientCertificate() (secureClientCert *x509.Certificate, ok bool)
	GetClientCertificate() (clientCert *x509.Certificate, ok bool)
	RenderHtml(html string, params any)
	RenderHtmlTemplate(tmpl *template.Template, params any)
}

type Client interface {
	GetId() (clientId string)
	GetName() (name string, ok bool)
	GetLogoUri() (logoUri string, ok bool)
	GetScopes() (scopes string, ok bool)
	GetPublicJwks() (clientJwks jose.JSONWebKeySet, err error)
	// Get the value of a custom attribute.
	GetAttribute(key string) (any, bool)
}

type DynamicClient interface {
	GetScopes() (scopes string, ok bool)
	SetScopes(scopes string)
	RequirePkce()
	RequireDpop()
	GetPublicJwks() (clientJwks jose.JSONWebKeySet, err error)
	// Set a custom attribute.
	SetAttribute(key string, value any)
	// Get the value of a custom attribute.
	GetAttribute(key string) (value any, ok bool)
}

type AuthnSession interface {
	// Set the user identifier. This value will be mapped to "sub" claim when issuing access and ID tokens,
	// as well as in the user info endpoint response.
	SetUserId(userId string)
	// Get the ID associate to the current user interaction.
	GetCallbackId() string
	// Get the scopes requested by the client.
	GetScopes() string
	// Get the prompt type requested by the client using the paramter "prompt".
	GetPromptType() (prompt PromptType, ok bool)
	GetMaxAuthenticationAgeSecs() (maxAge int, ok bool)
	// Get the display value requested by the client using the paramter "display".
	GetDisplayValue() (display DisplayValue, ok bool)
	// Get the ACR values requested by the client using the paramter "acr_values".
	GetAcrValues() ([]AuthenticationContextReference, bool)
	GetAuthorizationDetails() (details []AuthorizationDetail, ok bool)
	// Get the claims requested by the client using the parameter "claims".
	GetClaims() (claims ClaimsObject, ok bool)
	// Save a paramater in the session so it can be used across steps.
	SaveParameter(key string, value any)
	// Get a parameter saved in the session.
	GetParameter(key string) (value any, ok bool)
	// Set a new claim that will be mapped in the access token.
	AddTokenClaim(claim string, value any)
	// Set a new claim that will be mapped in the ID token.
	AddIdTokenClaim(claim string, value any)
	// Set a new claim that will be mapped in the user info endpoint.
	AddUserInfoClaim(claim string, value any)
	// Set the scopes the client will have access to use.
	GrantScopes(scopes string)
	GrantAuthorizationDetails(authDetails []AuthorizationDetail)
	// Get custom protected parameters sent during PAR (as form parameters) or JAR (as JSON keys).
	// The custom protect parameters are identified by the leading sequence "p_" in their name.
	GetProtectedParameter(key string) (value any, ok bool)
	// Define the error that will be redirected to the client.
	// This only has effect when a failure status is returned by the authentication policy.
	SetRedirectError(errorCode ErrorCode, errorDescription string)
}

// Function that will be executed during DCR and DCM.
// It can be used to modify the client and perform custom validations.
type DcrPluginFunc func(ctx Context, dynamicClient DynamicClient)

// Function responsible for executing the user authentication logic.
type AuthnFunc func(Context, AuthnSession) AuthnStatus

// Function responsible for deciding if the corresponding policy will be executed.
// It can be used to initialize the session as well.
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
	// The ID of a signing key present in the server JWKS.
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
