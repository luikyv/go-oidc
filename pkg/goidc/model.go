package goidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
)

type JWKSFunc func(context.Context) (JSONWebKeySet, error)

// RefreshTokenLength has an unusual value so to avoid refresh tokens and
// opaque access token to be confused.
// This happens since a refresh token is identified by its length during
// introspection.
const RefreshTokenLength int = 99

const DefaultOpaqueTokenLength int = 50

type Profile string

const (
	ProfileOpenID Profile = "openid"
	ProfileFAPI2  Profile = "fapi2"
	ProfileFAPI1  Profile = "fapi1"
)

func (p Profile) IsFAPI() bool {
	return p == ProfileFAPI1 || p == ProfileFAPI2
}

type GrantType string

const (
	GrantClientCredentials GrantType = "client_credentials"
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantImplicit          GrantType = "implicit"
	GrantJWTBearer         GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec
	GrantCIBA              GrantType = "urn:openid:params:grant-type:ciba"
)

type ResponseType string

const (
	ResponseTypeCode                   ResponseType = "code"
	ResponseTypeIDToken                ResponseType = "id_token"
	ResponseTypeToken                  ResponseType = "token"
	ResponseTypeCodeAndIDToken         ResponseType = "code id_token"
	ResponseTypeCodeAndToken           ResponseType = "code token"
	ResponseTypeIDTokenAndToken        ResponseType = "id_token token"
	ResponseTypeCodeAndIDTokenAndToken ResponseType = "code id_token token"
)

func (rt ResponseType) Contains(responseType ResponseType) bool {
	return slices.Contains(strings.Split(string(rt), " "), string(responseType))
}

func (rt ResponseType) IsImplicit() bool {
	return rt.Contains(ResponseTypeIDToken) || rt.Contains(ResponseTypeToken)
}

type ResponseMode string

const (
	ResponseModeQuery       ResponseMode = "query"
	ResponseModeFragment    ResponseMode = "fragment"
	ResponseModeFormPost    ResponseMode = "form_post"
	ResponseModeQueryJWT    ResponseMode = "query.jwt"
	ResponseModeFragmentJWT ResponseMode = "fragment.jwt"
	ResponseModeFormPostJWT ResponseMode = "form_post.jwt"
	ResponseModeJWT         ResponseMode = "jwt"
	// Redirectless response modes. These are not part of the official specification,
	// so use them with caution and only in controlled or experimental environments.
	ResponseModeJSON    ResponseMode = "json"
	ResponseModeJSONJWT ResponseMode = "json.jwt"
)

func (rm ResponseMode) IsJARM() bool {
	return rm == ResponseModeQueryJWT || rm == ResponseModeFragmentJWT ||
		rm == ResponseModeFormPostJWT || rm == ResponseModeJWT || rm == ResponseModeJSONJWT
}

func (rm ResponseMode) IsPlain() bool {
	return rm == ResponseModeQuery || rm == ResponseModeFragment ||
		rm == ResponseModeFormPost || rm == ResponseModeJSON
}

func (rm ResponseMode) IsQuery() bool {
	return rm == ResponseModeQuery || rm == ResponseModeQueryJWT
}

func (rm ResponseMode) IsJSON() bool {
	return rm == ResponseModeJSON || rm == ResponseModeJSONJWT
}

type ClientAuthnType string

const (
	ClientAuthnNone          ClientAuthnType = "none"
	ClientAuthnSecretBasic   ClientAuthnType = "client_secret_basic"
	ClientAuthnSecretPost    ClientAuthnType = "client_secret_post"
	ClientAuthnSecretJWT     ClientAuthnType = "client_secret_jwt"
	ClientAuthnPrivateKeyJWT ClientAuthnType = "private_key_jwt"
	ClientAuthnTLS           ClientAuthnType = "tls_client_auth"
	ClientAuthnSelfSignedTLS ClientAuthnType = "self_signed_tls_client_auth"
)

type ClientAssertionType string

const (
	AssertionTypeJWTBearer ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec
)

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
	TokenTypeDPoP   TokenType = "DPoP"
)

const (
	ClaimTokenID             string = "jti"
	ClaimIssuer              string = "iss"
	ClaimSubject             string = "sub"
	ClaimAudience            string = "aud"
	ClaimClientID            string = "client_id"
	ClaimExpiry              string = "exp"
	ClaimIssuedAt            string = "iat"
	ClaimNotBefore           string = "nbf"
	ClaimScope               string = "scope"
	ClaimNonce               string = "nonce"
	ClaimAuthTime            string = "auth_time"
	ClaimAMR                 string = "amr"
	ClaimACR                 string = "acr"
	ClaimProfile             string = "profile"
	ClaimEmail               string = "email"
	ClaimEmailVerified       string = "email_verified"
	ClaimPhoneNumber         string = "phone_number"
	ClaimPhoneNumberVerified string = "phone_number_verified"
	ClaimAddress             string = "address"
	ClaimName                string = "name"
	ClaimWebsite             string = "website"
	ClaimZoneInfo            string = "zoneinfo"
	ClaimBirthdate           string = "birthdate"
	ClaimGender              string = "gender"
	ClaimPreferredUsername   string = "preferred_username"
	ClaimGivenName           string = "given_name"
	ClaimMiddleName          string = "middle_name"
	ClaimLocale              string = "locale"
	ClaimPicture             string = "picture"
	ClaimUpdatedAt           string = "updated_at"
	ClaimNickname            string = "nickname"
	ClaimFamilyName          string = "family_name"
	ClaimAuthDetails         string = "authorization_details"
	ClaimAccessTokenHash     string = "at_hash"
	ClaimAuthzCodeHash       string = "c_hash"
	ClaimStateHash           string = "s_hash"
	ClaimRefreshTokenHash    string = "urn:openid:params:jwt:claim:rt_hash" //nolint:gosec
	ClaimAuthReqID           string = "urn:openid:params:jwt:claim:auth_req_id"
)

type KeyUsage string

const (
	KeyUsageSignature  KeyUsage = "sig"
	KeyUsageEncryption KeyUsage = "enc"
)

type CodeChallengeMethod string

const (
	CodeChallengeMethodSHA256 CodeChallengeMethod = "S256"
	CodeChallengeMethodPlain  CodeChallengeMethod = "plain"
)

// SubIdentifierType defines how the auth server provides subject
// identifiers to its clients.
// For more information,
// see: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
type SubIdentifierType string

const (
	// SubIdentifierPublic makes the server provide the same subject
	// identifier to all clients.
	SubIdentifierPublic   SubIdentifierType = "public"
	SubIdentifierPairwise SubIdentifierType = "pairwise"
)

type ApplicationType string

const (
	ApplicationTypeWeb    ApplicationType = "web"
	ApplicationTypeNative ApplicationType = "native"
)

const (
	HeaderDPoP string = "DPoP"
)

type Status string

const (
	StatusSuccess    Status = "success"
	StatusInProgress Status = "in_progress"
	StatusFailure    Status = "failure"
)

type TokenFormat string

const (
	TokenFormatJWT    TokenFormat = "jwt"
	TokenFormatOpaque TokenFormat = "opaque"
)

// AMR defines a type for authentication method references.
type AMR string

const (
	AMRFacialRecognition            AMR = "face"
	AMRFingerPrint                  AMR = "fpt"
	AMRGeolocation                  AMR = "geo"
	AMRHardwareSecuredKey           AMR = "hwk"
	AMRIrisScan                     AMR = "iris"
	AMRMultipleFactor               AMR = "mfa"
	AMROneTimePassoword             AMR = "otp"
	AMRPassword                     AMR = "pwd"
	AMRPersonalIDentificationNumber AMR = "pin"
	AMRRiskBased                    AMR = "rba"
	AMRSMS                          AMR = "sms"
	AMRSoftwareSecuredKey           AMR = "swk"
)

type DisplayValue string

const (
	DisplayValuePage  DisplayValue = "page"
	DisplayValuePopUp DisplayValue = "popup"
	DisplayValueTouch DisplayValue = "touch"
	DisplayValueWAP   DisplayValue = "wap"
)

type PromptType string

const (
	PromptTypeNone          PromptType = "none"
	PromptTypeLogin         PromptType = "login"
	PromptTypeConsent       PromptType = "consent"
	PromptTypeSelectAccount PromptType = "select_account"
)

type ClaimType string

const (
	ClaimTypeNormal      ClaimType = "normal"
	ClaimTypeAggregated  ClaimType = "aggregated"
	ClaimTypeDistributed ClaimType = "distributed"
)

type TokenTypeHint string

const (
	TokenHintAccess  TokenTypeHint = "access_token"
	TokenHintRefresh TokenTypeHint = "refresh_token"
)

// ACR defines a type for authentication context references.
type ACR string

const (
	ACRNoAssuranceLevel      ACR = "0"
	ACRMaceIncommonIAPSilver ACR = "urn:mace:incommon:iap:silver"
	ACRMaceIncommonIAPBronze ACR = "urn:mace:incommon:iap:bronze"
)

// ClientCertFunc fetches the client certificate during mTLS connections.
// It may be executed multiple times during a single request to the provider.
// Consider caching the certificate to avoid redundant computations.
type ClientCertFunc func(*http.Request) (*x509.Certificate, error)

type MiddlewareFunc func(next http.Handler) http.Handler

func ApplyMiddlewares(h http.Handler, middlewares ...MiddlewareFunc) http.Handler {
	for _, m := range middlewares {
		h = m(h)
	}
	return h
}

// HandleDynamicClientFunc defines a function that will be executed during DCR
// and DCM.
// It can be used to modify the client and perform custom validations.
type HandleDynamicClientFunc func(r *http.Request, id string, meta *ClientMeta) error

type ValidateInitialAccessTokenFunc func(*http.Request, string) error

type ClientIDFunc func(context.Context) string

// RenderErrorFunc defines a function that will be called when errors
// during the authorization request cannot be handled.
type RenderErrorFunc func(http.ResponseWriter, *http.Request, error) error

type NotifyErrorFunc func(context.Context, error)

var (
	ScopeOpenID        = NewScope("openid")
	ScopeProfile       = NewScope("profile")
	ScopeEmail         = NewScope("email")
	ScopePhone         = NewScope("phone")
	ScopeAddress       = NewScope("address")
	ScopeOfflineAccess = NewScope("offline_access")
)

// MatchScopeFunc defines a function executed to verify whether a requested
// scope is a match or not.
type MatchScopeFunc func(requestedScope string) bool

type Scope struct {
	// ID is the string representation of the scope.
	// Its value will be published as is in the well known endpoint.
	ID string
	// Matches validates if a requested scope matches the current scope.
	Matches MatchScopeFunc
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
	matchingFunc MatchScopeFunc,
) Scope {
	return Scope{
		ID:      scope,
		Matches: matchingFunc,
	}
}

// CheckJTIFunc defines a function to verify when a JTI is safe to use.
type CheckJTIFunc func(context.Context, string) error

// HTTPClientFunc defines a function that generates an HTTP client for performing
// requests.
// Note: Make sure to not enable automatic redirect-following, as some profiles
// require this behavior is disabled.
type HTTPClientFunc func(ctx context.Context) *http.Client

type ShouldIssueRefreshTokenFunc func(*Client, GrantInfo) bool

// TokenOptionsFunc defines a function that returns token configuration and is
// executed when issuing access tokens.
type TokenOptionsFunc func(GrantInfo, *Client) TokenOptions

// TokenOptions defines a template for generating access tokens.
type TokenOptions struct {
	Format       TokenFormat
	LifetimeSecs int
	JWTSigAlg    SignatureAlgorithm
	OpaqueLength int
}

func NewJWTTokenOptions(alg SignatureAlgorithm, lifetimeSecs int) TokenOptions {
	return TokenOptions{
		Format:       TokenFormatJWT,
		JWTSigAlg:    alg,
		LifetimeSecs: lifetimeSecs,
	}
}

func NewOpaqueTokenOptions(length int, lifetimeSecs int) TokenOptions {
	return TokenOptions{
		Format:       TokenFormatOpaque,
		LifetimeSecs: lifetimeSecs,
		OpaqueLength: length,
	}
}

// AuthnFunc executes the user authentication logic.
//
// If it returns [StatusSuccess], the flow will end successfully and the client
// will be granted the accesses the user consented.
//
// If it returns [StatusFailure] or an error the flow will end with failure and
// the client will be denied access.
//
// If it return [StatusInProgress], the flow will be suspended so an interaction
// with the user via the user agent can happen, e.g. an HTML page is rendered to
// to gather user credentials.
// The flow can be resumed at the callback endpoint with the session callback ID.
type AuthnFunc func(http.ResponseWriter, *http.Request, *AuthnSession) (Status, error)

type AuthnStep struct {
	ID        string
	AuthnFunc AuthnFunc
}

func NewAuthnStep(id string, authnFunc AuthnFunc) AuthnStep {
	return AuthnStep{
		ID:        id,
		AuthnFunc: authnFunc,
	}
}

type authnSteps []AuthnStep

func (steps authnSteps) Authenticate(w http.ResponseWriter, r *http.Request, as *AuthnSession) (Status, error) {
	// Initialize the step ID with the first step if not set.
	if as.StepID == "" {
		as.StepID = steps[0].ID
	}

	for idx, step := range steps {
		if as.StepID != step.ID {
			continue
		}

		// Execute the step function and early return if it ends in progress or failure.
		if status, err := step.AuthnFunc(w, r, as); status != StatusSuccess || err != nil {
			return status, err
		}

		// The current step succeeded, update the step ID to the next step.
		nextIdx := idx + 1
		// Return success if the current step is the last step.
		if nextIdx == len(steps) {
			return StatusSuccess, nil
		}

		// Update the step ID to the next step.
		// Note that the next value of step.ID will match the updated as.StepID.
		as.StepID = steps[nextIdx].ID
	}

	return StatusFailure, errors.New("invalid policy, access denied")
}

// SetUpAuthnFunc is responsible for initiating the authentication session.
// It returns true when the policy is ready to execute and false for when the
// policy should be skipped.
type SetUpAuthnFunc func(*http.Request, *Client, *AuthnSession) bool

// AuthnPolicy holds information on how to set up an authentication session and
// authenticate users.
type AuthnPolicy struct {
	ID           string
	SetUp        SetUpAuthnFunc
	Authenticate AuthnFunc
}

// NewPolicy creates an authentication policy that will be selected based on setUpFunc and that
// authenticates users with authnFunc.
func NewPolicy(id string, setUpFunc SetUpAuthnFunc, authnFunc AuthnFunc) AuthnPolicy {
	return AuthnPolicy{
		ID:           id,
		Authenticate: authnFunc,
		SetUp:        setUpFunc,
	}
}

// NewPolicyWithSteps creates an authentication policy composed of a sequence of steps.
// When a step succeeds, the session is updated to point to the next step.
// Once the final step succeeds, the authentication flow completes with success.
func NewPolicyWithSteps(id string, setUpFunc SetUpAuthnFunc, steps ...AuthnStep) AuthnPolicy {
	return NewPolicy(id, setUpFunc, authnSteps(steps).Authenticate)
}

type TokenConfirmation struct {
	JWKThumbprint        string `json:"jkt,omitempty"`
	ClientCertThumbprint string `json:"x5t#S256,omitempty"`
}

type TokenInfo struct {
	// GrantID is the ID of the grant session associated to token.
	GrantID               string                `json:"-"`
	IsActive              bool                  `json:"active"`
	Type                  TokenTypeHint         `json:"token_type,omitempty"`
	Scopes                string                `json:"scope,omitempty"`
	AuthorizationDetails  []AuthorizationDetail `json:"authorization_details,omitempty"`
	ResourceAudiences     Resources             `json:"aud,omitempty"`
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
	maps.Copy(rawValues, ti.AdditionalTokenClaims)

	return json.Marshal(rawValues)
}

type AuthorizationParameters struct {
	RequestURI              string                `json:"request_uri,omitempty"`
	RequestObject           string                `json:"request,omitempty"`
	RedirectURI             string                `json:"redirect_uri,omitempty"`
	ResponseMode            ResponseMode          `json:"response_mode,omitempty"`
	ResponseType            ResponseType          `json:"response_type,omitempty"`
	Scopes                  string                `json:"scope,omitempty"`
	State                   string                `json:"state,omitempty"`
	Nonce                   string                `json:"nonce,omitempty"`
	CodeChallenge           string                `json:"code_challenge,omitempty"`
	CodeChallengeMethod     CodeChallengeMethod   `json:"code_challenge_method,omitempty"`
	Prompt                  PromptType            `json:"prompt,omitempty"`
	MaxAuthnAgeSecs         *int                  `json:"max_age,omitempty"`
	Display                 DisplayValue          `json:"display,omitempty"`
	ACRValues               string                `json:"acr_values,omitempty"`
	Claims                  *ClaimsObject         `json:"claims,omitempty"`
	AuthDetails             []AuthorizationDetail `json:"authorization_details,omitempty"`
	Resources               Resources             `json:"resource,omitempty"`
	DPoPJKT                 string                `json:"dpop_jkt,omitempty"`
	LoginHint               string                `json:"login_hint,omitempty"`
	LoginTokenHint          string                `json:"login_hint_token,omitempty"`
	IDTokenHint             string                `json:"id_token_hint,omitempty"`
	ClientNotificationToken string                `json:"client_notification_token,omitempty"`
	BindingMessage          string                `json:"binding_message,omitempty"`
	UserCode                string                `json:"user_code,omitempty"`
	RequestedExpiry         *int                  `json:"requested_expiry,omitempty"`
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
// It is a map instead of a struct, because its fields vary a lot depending on
// the use case.
type AuthorizationDetail map[string]any

func (d AuthorizationDetail) Type() string {
	return d.string("type")
}

func (d AuthorizationDetail) Identifier() string {
	return d.string("identifier")
}

func (d AuthorizationDetail) Locations() []string {
	return d.stringSlice("locations")
}

func (d AuthorizationDetail) Actions() []string {
	return d.stringSlice("actions")
}

func (d AuthorizationDetail) DataTypes() []string {
	return d.stringSlice("datatypes")
}

func (d AuthorizationDetail) stringSlice(key string) []string {
	value, ok := d[key]
	if !ok {
		return nil
	}

	slice, ok := value.([]string)
	if !ok {
		return nil
	}

	return slice
}

func (d AuthorizationDetail) string(key string) string {
	value, ok := d[key]
	if !ok {
		return ""
	}

	s, ok := value.(string)
	if !ok {
		return ""
	}

	return s
}

type HandleJWTBearerGrantAssertionFunc func(r *http.Request, assertion string) (JWTBearerGrantInfo, error)

type JWTBearerGrantInfo struct {
	Subject string
	Store   map[string]any
}

type IsClientAllowedFunc func(*Client) bool

type IsClientAllowedTokenInstrospectionFunc func(*Client, TokenInfo) bool

// CompareAuthDetailsFunc defines a function used in authorization_code and
// refresh_token grant types to validate that the requested authorization details
// are consistent with the granted ones.
type CompareAuthDetailsFunc func(granted, requested []AuthorizationDetail) error

type GeneratePairwiseSubIDFunc func(ctx context.Context, sub string, client *Client) string

type CIBATokenDeliveryMode string

const (
	CIBATokenDeliveryModePoll CIBATokenDeliveryMode = "poll"
	CIBATokenDeliveryModePing CIBATokenDeliveryMode = "ping"
	CIBATokenDeliveryModePush CIBATokenDeliveryMode = "push"
)

func (mode CIBATokenDeliveryMode) IsNotificationMode() bool {
	return mode == CIBATokenDeliveryModePing || mode == CIBATokenDeliveryModePush
}

func (mode CIBATokenDeliveryMode) IsPollableMode() bool {
	return mode == CIBATokenDeliveryModePoll || mode == CIBATokenDeliveryModePing
}

// InitBackAuthFunc allows modifying the authn session when initializing the
// CIBA process.
// If an error is returned, the authentication flow will not be initiated.
type InitBackAuthFunc func(context.Context, *AuthnSession) error

// ValidateBackAuthFunc validates a CIBA session during a client's polling
// request to the token endpoint.
// If an error other than [ErrorCodeAuthPending] or [ErrorCodeSlowDown] is
// returned, the session will be terminated.
type ValidateBackAuthFunc func(context.Context, *AuthnSession) error

type ClientRegistrationType string

const (
	ClientRegistrationTypeAutomatic ClientRegistrationType = "automatic"
	ClientRegistrationTypeExplicit  ClientRegistrationType = "explicit"
)

type RequiredTrustMarksFunc func(context.Context) []string

type HandleSessionFunc func(*http.Request, *AuthnSession, *Client) error

type LogoutParameters struct {
	IDTokenHint           string `json:"id_token_hint,omitempty"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri,omitempty"`
	State                 string `json:"state,omitempty"`
	UILocales             string `json:"ui_locales,omitempty"`
	LogoutHint            string `json:"logout_hint,omitempty"`
}

type DefaultRedirectURIFunc func(context.Context, *LogoutSession) string

type SetUpLogoutFunc func(*http.Request, *LogoutSession) bool

type LogoutFunc func(http.ResponseWriter, *http.Request, *LogoutSession) (Status, error)

// LogoutPolicy holds information on how to set up a logout session and
// validate a logout request.
type LogoutPolicy struct {
	ID     string
	SetUp  SetUpLogoutFunc
	Logout LogoutFunc
}

func NewLogoutPolicy(id string, setUpFunc SetUpLogoutFunc, logoutFunc LogoutFunc) LogoutPolicy {
	return LogoutPolicy{
		ID:     id,
		SetUp:  setUpFunc,
		Logout: logoutFunc,
	}
}

func NewLogoutPolicyWithSteps(id string, setUpFunc SetUpLogoutFunc, steps ...LogoutStep) LogoutPolicy {
	return NewLogoutPolicy(id, setUpFunc, logoutSteps(steps).Logout)
}

type LogoutStep struct {
	ID     string
	Logout LogoutFunc
}

type logoutSteps []LogoutStep

func (steps logoutSteps) Logout(w http.ResponseWriter, r *http.Request, ls *LogoutSession) (Status, error) {
	// Initialize the step ID with the first step if not set.
	if ls.StepID == "" {
		ls.StepID = steps[0].ID
	}

	for idx, step := range steps {
		if ls.StepID != step.ID {
			continue
		}

		// Execute the step function and early return if it ends in progress or failure.
		if status, err := step.Logout(w, r, ls); status != StatusSuccess || err != nil {
			return status, err
		}

		// The current step succeeded, update the step ID to the next step.
		nextIdx := idx + 1
		// Return success if the current step is the last step.
		if nextIdx == len(steps) {
			return StatusSuccess, nil
		}

		// Update the step ID to the next step.
		// Note that the next value of step.ID will match the updated as.StepID.
		ls.StepID = steps[nextIdx].ID
	}

	return StatusFailure, errors.New("invalid policy, access denied")
}
