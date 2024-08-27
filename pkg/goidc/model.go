package goidc

import (
	"crypto/x509"
	"encoding/json"
	"maps"
	"net/http"
)

type ClientCertFunc func(r *http.Request) (*x509.Certificate, bool)

type MiddlewareFunc func(next http.Handler) http.Handler

// DCRFunc defines a function that will be executed during DCR and DCM.
// It can be used to modify the client and perform custom validations.
type DCRFunc func(r *http.Request, c *ClientMetaInfo) error

// AuthorizeErrorFunc defines a function that will be called when errors
// during the authorization request cannot be handled.
type AuthorizeErrorFunc func(w http.ResponseWriter, r *http.Request, err error) error

type HandleErrorEventFunc func(r *http.Request, err error)

var (
	ScopeOpenID        = NewScope("openid")
	ScopeProfile       = NewScope("profile")
	ScopeEmail         = NewScope("email")
	ScopeAddress       = NewScope("address")
	ScopeOfflineAccess = NewScope("offline_access")
)

// ScopeMatchingFunc defines a function executed to verify whether a requested
// scope matches the current one.
type ScopeMatchingFunc func(requestedScope string) bool

type Scope struct {
	// ID is the string representation of the scope.
	// Its value will be published as is in the well known endpoint.
	ID string
	// Matches validates if a requested scope is valid.
	Matches ScopeMatchingFunc
}

// NewScope creates a scope where the validation logic is simple string comparison.
func NewScope(scope string) Scope {
	return Scope{
		ID: scope,
		Matches: func(requestedScope string) bool {
			return scope == requestedScope
		},
	}
}

// NewDynamicScope creates a scope with custom logic that will be used to validate
// the scopes requested by the client.
//
//	dynamicScope := NewDynamicScope(
//		"payment",
//		func(requestedScope string) bool {
//			return strings.HasPrefix(requestedScope, "payment:")
//		},
//	)
//
//	// This results in true.
//	dynamicScope.Matches("payment:30")
func NewDynamicScope(
	scope string,
	matchingFunc ScopeMatchingFunc,
) Scope {
	return Scope{
		ID:      scope,
		Matches: matchingFunc,
	}
}

// TokenOptionsFunc defines a function that returns token configuration and is
// executed when issuing access tokens.
type TokenOptionsFunc func(client *Client, scopes string) (TokenOptions, error)

// TokenOptions defines a template for generating access tokens.
type TokenOptions struct {
	Format            TokenFormat    `json:"token_format"`
	LifetimeSecs      int            `json:"token_lifetime_secs"`
	JWTSignatureKeyID string         `json:"token_signature_key_id,omitempty"`
	OpaqueLength      int            `json:"opaque_token_length,omitempty"`
	IsRefreshable     bool           `json:"-"`
	AdditionalClaims  map[string]any `json:"additional_token_claims,omitempty"`
}

func (to *TokenOptions) AddTokenClaims(claims map[string]any) {
	if to.AdditionalClaims == nil {
		to.AdditionalClaims = map[string]any{}
	}
	maps.Copy(to.AdditionalClaims, claims)
}

func NewJWTTokenOptions(
	// signatureKeyID is the ID of a signing key present in the server JWKS.
	signatureKeyID string,
	lifetimeSecs int,
) TokenOptions {
	return TokenOptions{
		Format:            TokenFormatJWT,
		LifetimeSecs:      lifetimeSecs,
		JWTSignatureKeyID: signatureKeyID,
	}
}

func NewOpaqueTokenOptions(
	tokenLength int,
	lifetimeSecs int,
) TokenOptions {
	return TokenOptions{
		Format:       TokenFormatOpaque,
		LifetimeSecs: lifetimeSecs,
		OpaqueLength: tokenLength,
	}
}

// AuthnFunc executes the user authentication logic.
type AuthnFunc func(http.ResponseWriter, *http.Request, *AuthnSession) AuthnStatus

// SetUpAuthnFunc is responsible for initiating the authentication session.
//
// It returns true when the policy is ready to executed and false for when the
// policy should be skipped.
type SetUpAuthnFunc func(*http.Request, *Client, *AuthnSession) bool

// AuthnPolicy holds information on how to set up an authentication session and
// authenticate users.
type AuthnPolicy struct {
	ID           string
	SetUp        SetUpAuthnFunc
	Authenticate AuthnFunc
}

// NewPolicy creates a policy that will be selected based on setUpFunc and that
// authenticates users with authnFunc.
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

type TokenConfirmation struct {
	JWKThumbprint               string `json:"jkt"`
	ClientCertificateThumbprint string `json:"x5t#S256"`
}

type TokenInfo struct {
	IsActive              bool                  `json:"active"`
	Type                  TokenTypeHint         `json:"hint,omitempty"`
	Scopes                string                `json:"scope,omitempty"`
	AuthorizationDetails  []AuthorizationDetail `json:"authorization_details,omitempty"`
	ClientID              string                `json:"client_id,omitempty"`
	Subject               string                `json:"sub,omitempty"`
	ExpiresAtTimestamp    int                   `json:"exp,omitempty"`
	Confirmation          *TokenConfirmation    `json:"cnf,omitempty"`
	AdditionalTokenClaims map[string]any        `json:"-"`
}

func (ti TokenInfo) MarshalJSON() ([]byte, error) {

	type tokenInfo TokenInfo
	attributesBytes, err := json.Marshal(tokenInfo(ti))
	if err != nil {
		return nil, err
	}

	var rawValues map[string]any
	if err := json.Unmarshal(attributesBytes, &rawValues); err != nil {
		return nil, err
	}

	// Inline the additional claims.
	for k, v := range ti.AdditionalTokenClaims {
		rawValues[k] = v
	}

	return json.Marshal(rawValues)
}

type AuthorizationParameters struct {
	RequestURI           string                `json:"request_uri,omitempty"`
	RequestObject        string                `json:"request,omitempty"`
	RedirectURI          string                `json:"redirect_uri,omitempty"`
	ResponseMode         ResponseMode          `json:"response_mode,omitempty"`
	ResponseType         ResponseType          `json:"response_type,omitempty"`
	Scopes               string                `json:"scope,omitempty"`
	State                string                `json:"state,omitempty"`
	Nonce                string                `json:"nonce,omitempty"`
	CodeChallenge        string                `json:"code_challenge,omitempty"`
	CodeChallengeMethod  CodeChallengeMethod   `json:"code_challenge_method,omitempty"`
	Prompt               PromptType            `json:"prompt,omitempty"`
	MaxAuthnAgeSecs      *int                  `json:"max_age,omitempty"`
	Display              DisplayValue          `json:"display,omitempty"`
	ACRValues            string                `json:"acr_values,omitempty"`
	Claims               *ClaimsObject         `json:"claims,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
	Resources            Resources             `json:"resource,omitempty"`
}

type Resources []string

func (r *Resources) UnmarshalJSON(data []byte) error {
	var resource string
	if err := json.Unmarshal(data, &resource); err == nil {
		*r = []string{resource}
		return nil
	}

	var resources []string
	if err := json.Unmarshal(data, &resources); err != nil {
		return err
	}

	*r = resources
	return nil
}

func (resources Resources) MarshalJSON() ([]byte, error) {
	if len(resources) == 1 {
		return json.Marshal(resources[0])
	}

	return json.Marshal([]string(resources))
}

type ClaimsObject struct {
	UserInfo map[string]ClaimObjectInfo `json:"userinfo"`
	IDToken  map[string]ClaimObjectInfo `json:"id_token"`
}

// UserInfoEssentials returns all the essentials claims requested by the client
// to be returned in the userinfo endpoint.
func (claims ClaimsObject) UserInfoEssentials() []string {
	return essentials(claims.UserInfo)
}

// IDTokenEssentials returns all the essentials claims requested by the client
// to be returned in the ID token.
func (claims ClaimsObject) IDTokenEssentials() []string {
	return essentials(claims.IDToken)
}

// UserInfoClaim returns the claim object info if present.
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

// AuthorizationDetail represents an authorization details as a map.
//
// It is a map instead of a struct, because its fields vary a lot depending on
// the use case.
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
