package goidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
)

// GrantManager stores grants.
type GrantManager interface {
	SaveGrant(context.Context, *Grant) error
	// Grant returns the grant identified by id.
	// It must return [ErrNotFound] when the grant does not exist.
	Grant(context.Context, string) (*Grant, error)
}

// AuthManager stores authorization sessions and resolves grants by
// authorization code.
type AuthManager interface {
	SaveSession(context.Context, *AuthnSession) error
	// Session returns the authorization session identified by id.
	// It must return [ErrNotFound] when the session does not exist.
	Session(context.Context, string) (*AuthnSession, error)
	// GrantByAuthCode returns the grant associated with the authorization code.
	// It must return [ErrNotFound] when the grant does not exist.
	GrantByAuthCode(context.Context, string) (*Grant, error)
}

// PARManager resolves pushed authorization request sessions.
type PARManager interface {
	// SessionByPushedAuthReqID returns the session associated with the pushed
	// authorization request identifier.
	// It must return [ErrNotFound] when the session does not exist.
	SessionByPushedAuthReqID(context.Context, string) (*AuthnSession, error)
}

// DCRManager stores dynamically registered clients.
type DCRManager interface {
	SaveClient(context.Context, *Client) error
	// Client returns the client identified by id.
	// It must return [ErrNotFound] when the client does not exist.
	Client(context.Context, string) (*Client, error)
	DeleteClient(context.Context, string) error
}

// OpenIDFedManager stores OpenID Federation clients.
type OpenIDFedManager interface {
	SaveClient(context.Context, *Client) error
	// Client returns the federation client identified by id.
	// It must return [ErrNotFound] when the client does not exist.
	Client(context.Context, string) (*Client, error)
}

// RefreshTokenManager resolves grants by refresh token.
type RefreshTokenManager interface {
	// GrantByRefreshToken returns the grant associated with the refresh token.
	// It must return [ErrNotFound] when the grant does not exist.
	GrantByRefreshToken(context.Context, string) (*Grant, error)
}

// CIBAManager stores CIBA sessions and resolves grants by auth_req_id.
type CIBAManager interface {
	SaveSession(context.Context, *AuthnSession) error
	// Session returns the CIBA session identified by id.
	// It must return [ErrNotFound] when the session does not exist.
	Session(context.Context, string) (*AuthnSession, error)
	// SessionByAuthReqID returns the session associated with the auth_req_id.
	// It must return [ErrNotFound] when the session does not exist.
	SessionByAuthReqID(context.Context, string) (*AuthnSession, error)
	// GrantByAuthReqID returns the grant associated with the auth_req_id.
	// It must return [ErrNotFound] when the grant does not exist.
	GrantByAuthReqID(context.Context, string) (*Grant, error)
}

// DeviceAuthManager stores device authorization sessions and resolves grants by
// device code.
type DeviceAuthManager interface {
	SaveSession(context.Context, *AuthnSession) error
	// Session returns the device authorization session identified by id.
	// It must return [ErrNotFound] when the session does not exist.
	Session(context.Context, string) (*AuthnSession, error)
	// SessionByUserCode returns the session associated with the user code.
	// It must return [ErrNotFound] when the session does not exist.
	SessionByUserCode(context.Context, string) (*AuthnSession, error)
	// SessionByDeviceCode returns the session associated with the device code.
	// It must return [ErrNotFound] when the session does not exist.
	SessionByDeviceCode(context.Context, string) (*AuthnSession, error)
	// GrantByDeviceCode returns the grant associated with the device code.
	// It must return [ErrNotFound] when the grant does not exist.
	GrantByDeviceCode(context.Context, string) (*Grant, error)
}

// OpaqueTokenManager stores and retrieves opaque access tokens.
// It is only required when opaque tokens are enabled.
type OpaqueTokenManager interface {
	SaveToken(context.Context, *Token) error
	// Token returns the token identified by id.
	// It must return [ErrNotFound] when the token does not exist.
	Token(context.Context, string) (*Token, error)
}

type JWKSFunc func(context.Context) (JSONWebKeySet, error)

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
	GrantPreAuthorizedCode GrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	GrantDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTokenExchange     GrantType = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec
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

type AuthnMethod string

const (
	AuthnMethodNone           AuthnMethod = "none"
	AuthnMethodSecretBasic    AuthnMethod = "client_secret_basic"
	AuthnMethodSecretPost     AuthnMethod = "client_secret_post"
	AuthnMethodSecretJWT      AuthnMethod = "client_secret_jwt"
	AuthnMethodPrivateKeyJWT  AuthnMethod = "private_key_jwt"
	AuthnMethodTLS            AuthnMethod = "tls_client_auth"
	AuthnMethodSelfSignedTLS  AuthnMethod = "self_signed_tls_client_auth"
	AuthnMethodAttestationJWT AuthnMethod = "attest_jwt_client_auth"
)

type ClientAssertionType string

const (
	AssertionTypeJWTBearer ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec
)

type TokenType string

const (
	TokenTypeBearer TokenType = "Bearer"
	TokenTypeDPoP   TokenType = "DPoP"
	// TokenTypeNotApplicable indicates the issued token is not an access token or
	// usable as an access token.
	TokenTypeNotApplicable TokenType = "N_A"
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
	ClaimGrantID             string = "grant_id"
	ClaimAct                 string = "act"
	ClaimMayAct              string = "may_act"
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
	StatusSuccess Status = "success"
	StatusPending Status = "pending"
	StatusFailure Status = "failure"
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
	AMRFingerprint                  AMR = "fpt"
	AMRGeolocation                  AMR = "geo"
	AMRHardwareSecuredKey           AMR = "hwk"
	AMRIrisScan                     AMR = "iris"
	AMRMultipleFactor               AMR = "mfa"
	AMROneTimePassword              AMR = "otp"
	AMRPassword                     AMR = "pwd"
	AMRPersonalIdentificationNumber AMR = "pin"
	AMRRiskBased                    AMR = "rba"
	AMRSMS                          AMR = "sms"
	AMRSoftwareSecuredKey           AMR = "swk"
)

type DisplayValue string

const (
	DisplayValuePage  DisplayValue = "page"
	DisplayValuePopup DisplayValue = "popup"
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
type ClientCertFunc func(context.Context) (*x509.Certificate, error)

type MiddlewareFunc func(next http.Handler) http.Handler

func ApplyMiddlewares(h http.Handler, middlewares ...MiddlewareFunc) http.Handler {
	for _, middleware := range middlewares {
		h = middleware(h)
	}
	return h
}

// DCRHandleClientFunc defines a function that will be executed during DCR and DCM.
// It can be used to modify the client and perform custom validations.
type DCRHandleClientFunc func(ctx context.Context, id string, meta *ClientMeta) error

type DCRValidateInitialTokenFunc func(context.Context, string) error

type ClientIDFunc func(context.Context) string

// RenderErrorFunc defines a function that will be called when errors
// during the authorization request cannot be handled.
type RenderErrorFunc func(http.ResponseWriter, *http.Request, error) error

type HandleErrorFunc func(context.Context, error)

type VerifyClientSecretFunc func(ctx context.Context, stored, presented string) error

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
	// Its value will be published as is in the openid configuration endpoint.
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
func NewDynamicScope(scope string, matchingFunc MatchScopeFunc) Scope {
	return Scope{
		ID:      scope,
		Matches: matchingFunc,
	}
}

// ConsumeJTIFunc defines a function to verify when a JTI is safe to use.
type ConsumeJTIFunc func(context.Context, string) error

// HTTPClientFunc defines a function that generates an HTTP client for performing
// requests.
// Note: Make sure to not enable automatic redirect-following, as some profiles
// require this behavior is disabled.
type HTTPClientFunc func(context.Context) *http.Client

type RefreshTokenShouldIssueFunc func(context.Context, *Client, *Grant) bool

// TokenOptionsFunc defines a function that returns token configuration and is
// executed when issuing access tokens.
type TokenOptionsFunc func(context.Context, *Grant, *Client) TokenOptions

// OpaqueTokenFunc defines how opaque access token identifiers are generated.
type OpaqueTokenFunc func(context.Context, *Grant) string

// IDTokenClaimsFunc defines a function that returns additional claims to include
// in the ID token. It is called at ID token issuance time.
type IDTokenClaimsFunc func(context.Context, *Grant) map[string]any

// UserInfoClaimsFunc defines a function that returns additional claims to include
// in the userinfo response. It is called when the userinfo endpoint is requested.
type UserInfoClaimsFunc func(context.Context, *Grant) map[string]any

// TokenClaimsFunc defines a function that returns additional claims to include
// in JWT access tokens. It is called at access token issuance time.
type TokenClaimsFunc func(context.Context, *Token, *Grant) map[string]any

// TokenOptions defines a template for generating access tokens.
type TokenOptions struct {
	Format       TokenFormat
	LifetimeSecs int
	JWTSigAlg    SignatureAlgorithm
}

func NewJWTTokenOptions(alg SignatureAlgorithm, lifetimeSecs int) TokenOptions {
	return TokenOptions{
		Format:       TokenFormatJWT,
		JWTSigAlg:    alg,
		LifetimeSecs: lifetimeSecs,
	}
}

func NewOpaqueTokenOptions(lifetimeSecs int) TokenOptions {
	return TokenOptions{
		Format:       TokenFormatOpaque,
		LifetimeSecs: lifetimeSecs,
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
// If it returns [StatusPending], the flow will be suspended so an interaction
// with the user via the user agent can happen, e.g. an HTML page is rendered to
// to gather user credentials.
// The flow can be resumed at the callback endpoint with the session callback ID.
type AuthnFunc func(http.ResponseWriter, *http.Request, *AuthnSession, *Client) (Status, error)

// SetupAuthnFunc is responsible for initiating the authentication session.
// It returns true when the policy is ready to execute and false for when the
// policy should be skipped.
type SetupAuthnFunc func(*http.Request, *AuthnSession, *Client) bool

// AuthnPolicy holds information on how to set up an authentication session and
// authenticate users.
type AuthnPolicy struct {
	ID           string
	Setup        SetupAuthnFunc
	Authenticate AuthnFunc
}

// NewPolicy creates an authentication policy that will be selected based on setUpFunc and that
// authenticates users with authnFunc.
func NewPolicy(id string, setupFunc SetupAuthnFunc, authnFunc AuthnFunc) AuthnPolicy {
	return AuthnPolicy{
		ID:           id,
		Authenticate: authnFunc,
		Setup:        setupFunc,
	}
}

type TokenConfirmation struct {
	JWKThumbprint  string `json:"jkt,omitempty"`
	CertThumbprint string `json:"x5t#S256,omitempty"`
}

type TokenInfo struct {
	// GrantID is the ID of the grant associated to token.
	GrantID           string       `json:"grant_id,omitempty"`
	IsActive          bool         `json:"active"`
	Type              TokenType    `json:"token_type,omitempty"`
	Scopes            string       `json:"scope,omitempty"`
	AuthDetails       []AuthDetail `json:"authorization_details,omitempty"`
	ResourceAudiences Resources    `json:"aud,omitempty"`
	ClientID          string       `json:"client_id,omitempty"`
	Subject           string       `json:"sub,omitempty"`
	// [RFC 7662 §2.2] Username is a human-readable identifier for the resource owner.
	Username         string             `json:"username,omitempty"`
	Issuer           string             `json:"iss,omitempty"`
	IssuedAt         int                `json:"iat,omitempty"`
	NotBefore        int                `json:"nbf,omitempty"`
	ExpiresAt        int                `json:"exp,omitempty"`
	Confirmation     *TokenConfirmation `json:"cnf,omitempty"`
	Actor            *Actor             `json:"act,omitempty"`
	AdditionalClaims map[string]any     `json:"-"`
}

func (ti *TokenInfo) UnmarshalJSON(data []byte) error {
	type tokenInfo TokenInfo
	if err := json.Unmarshal(data, (*tokenInfo)(ti)); err != nil {
		return err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	t := reflect.TypeFor[tokenInfo]()
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if name, _, _ := strings.Cut(tag, ","); name != "" && name != "-" {
			delete(raw, name)
		}
	}

	if len(raw) > 0 {
		ti.AdditionalClaims = raw
	}

	return nil
}

func (ti TokenInfo) MarshalJSON() ([]byte, error) {
	if !ti.IsActive {
		return json.Marshal(map[string]any{"active": false})
	}

	type tokenInfo TokenInfo
	attributesBytes, err := json.Marshal(tokenInfo(ti))
	if err != nil {
		return nil, err
	}

	var rawValues map[string]any
	if err := json.Unmarshal(attributesBytes, &rawValues); err != nil {
		return nil, err
	}
	delete(rawValues, "grant_id")
	// Inline the additional claims.
	maps.Copy(rawValues, ti.AdditionalClaims)

	return json.Marshal(rawValues)
}

type AuthorizationParameters struct {
	RequestURI              string              `json:"request_uri,omitempty"`
	RequestObject           string              `json:"request,omitempty"`
	RedirectURI             string              `json:"redirect_uri,omitempty"`
	ResponseMode            ResponseMode        `json:"response_mode,omitempty"`
	ResponseType            ResponseType        `json:"response_type,omitempty"`
	Scopes                  string              `json:"scope,omitempty"`
	State                   string              `json:"state,omitempty"`
	Nonce                   string              `json:"nonce,omitempty"`
	CodeChallenge           string              `json:"code_challenge,omitempty"`
	CodeChallengeMethod     CodeChallengeMethod `json:"code_challenge_method,omitempty"`
	Prompt                  PromptType          `json:"prompt,omitempty"`
	MaxAuthnAgeSecs         *int                `json:"max_age,omitempty"`
	Display                 DisplayValue        `json:"display,omitempty"`
	ACRValues               string              `json:"acr_values,omitempty"`
	Claims                  *ClaimsObject       `json:"claims,omitempty"`
	AuthDetails             []AuthDetail        `json:"authorization_details,omitempty"`
	Resources               Resources           `json:"resource,omitempty"`
	DPoPJKT                 string              `json:"dpop_jkt,omitempty"`
	LoginHint               string              `json:"login_hint,omitempty"`
	LoginHintToken          string              `json:"login_hint_token,omitempty"`
	IDTokenHint             string              `json:"id_token_hint,omitempty"`
	ClientNotificationToken string              `json:"client_notification_token,omitempty"`
	BindingMessage          string              `json:"binding_message,omitempty"`
	UserCode                string              `json:"user_code,omitempty"`
	RequestedExpiry         *int                `json:"requested_expiry,omitempty"`
	IssuerState             string              `json:"issuer_state,omitempty"`
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

type AuthDetailType string

const (
	AuthDetailTypeOpenIDCredential AuthDetailType = "openid_credential" //nolint:gosec
)

type RARValidateDetailFunc func(context.Context, AuthDetail) error

// RARCompareDetailsFunc defines a function used in authorization_code and
// refresh_token grant types to validate that the requested authorization details
// are consistent with the granted ones.
type RARCompareDetailsFunc func(ctx context.Context, requested, granted []AuthDetail) error

// AuthDetail represents an authorization details as a map.
// It is a map instead of a struct, because its fields vary a lot depending on
// the use case.
type AuthDetail map[string]any

func (d AuthDetail) Type() AuthDetailType {
	value, ok := d["type"]
	if !ok {
		return ""
	}
	typ, _ := value.(string)
	return AuthDetailType(typ)
}

func (d AuthDetail) Locations() []string {
	value, ok := d["locations"]
	if !ok {
		return nil
	}
	rawLocs, ok := value.([]any)
	if !ok {
		return nil
	}
	var locs []string
	for _, rawLoc := range rawLocs {
		if loc, ok := rawLoc.(string); ok {
			locs = append(locs, loc)
		}
	}
	return locs
}

type JWTBearerResult struct {
	Subject string
	Store   map[string]any
}

type JWTBearerHandleAssertionFunc func(context.Context, string) (JWTBearerResult, error)

type IsClientAllowedFunc func(context.Context, *Client) bool

type IsClientAllowedTokenIntrospectionFunc func(context.Context, *Client, TokenInfo) bool

type PairwiseSubjectFunc func(ctx context.Context, sub string, client *Client) string

type CIBAProfile string

const (
	CIBAProfileOpenID CIBAProfile = "openid"
	CIBAProfileFAPI   CIBAProfile = "fapi"
)

type CIBATokenDeliveryMode string

const (
	CIBADeliveryModePoll CIBATokenDeliveryMode = "poll"
	CIBADeliveryModePing CIBATokenDeliveryMode = "ping"
	CIBADeliveryModePush CIBATokenDeliveryMode = "push"
)

func (mode CIBATokenDeliveryMode) IsNotificationMode() bool {
	return mode == CIBADeliveryModePing || mode == CIBADeliveryModePush
}

func (mode CIBATokenDeliveryMode) IsPollableMode() bool {
	return mode == CIBADeliveryModePoll || mode == CIBADeliveryModePing
}

type HandleSessionFunc func(context.Context, *AuthnSession, *Client) error

type LogoutParameters struct {
	IDTokenHint           string `json:"id_token_hint,omitempty"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri,omitempty"`
	State                 string `json:"state,omitempty"`
	UILocales             string `json:"ui_locales,omitempty"`
	LogoutHint            string `json:"logout_hint,omitempty"`
}

type HandleDefaultPostLogoutFunc func(http.ResponseWriter, *http.Request, *LogoutSession) error

type SetupLogoutFunc func(*http.Request, *LogoutSession) bool

type LogoutFunc func(http.ResponseWriter, *http.Request, *LogoutSession) (Status, error)

// LogoutPolicy holds information on how to set up a logout session and
// validate a logout request.
type LogoutPolicy struct {
	ID     string
	Setup  SetupLogoutFunc
	Logout LogoutFunc
}

func NewLogoutPolicy(id string, setupFunc SetupLogoutFunc, logoutFunc LogoutFunc) LogoutPolicy {
	return LogoutPolicy{
		ID:     id,
		Setup:  setupFunc,
		Logout: logoutFunc,
	}
}

type RandomFunc func(context.Context) string

type HandleClientFunc func(context.Context, *Client) error

type RenderFunc func(http.ResponseWriter, *http.Request) error

type AttestationIssuer struct {
	Issuer  string
	JWKSURI string
	SigAlgs []SignatureAlgorithm
}

// TokenTypeIdentifier indicates the type of a security token as defined in [RFC 8693 §3].
type TokenTypeIdentifier string

const (
	TokenTypeIdentifierJWT          TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:jwt"           //nolint:gosec
	TokenTypeIdentifierAccessToken  TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:access_token"  //nolint:gosec
	TokenTypeIdentifierRefreshToken TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:refresh_token" //nolint:gosec
	TokenTypeIdentifierIDToken      TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:id_token"      //nolint:gosec
	TokenTypeIdentifierSAML1        TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:saml1"         //nolint:gosec
	TokenTypeIdentifierSAML2        TokenTypeIdentifier = "urn:ietf:params:oauth:token-type:saml2"         //nolint:gosec
)

type TokenExchangeRequest struct {
	RequestedTokenType TokenTypeIdentifier
	// SubjectToken is a security token that represents the identity of the
	// party on behalf of whom the request is being made.
	SubjectToken     string
	SubjectTokenType TokenTypeIdentifier
	// ActorToken is a security token that represents the identity of the acting party.
	ActorToken     string
	ActorTokenType TokenTypeIdentifier
	// Audience is the logical name of the target service where the client
	// intends to use the requested security token.
	Audience []string
	// Resource is a URI that indicates the target service or resource where
	// the client intends to use the requested security token.
	Resource Resources
}

type TokenExchangeResult struct {
	Subject string
	Actor   *Actor
	Store   map[string]any
}

type TokenExchangeHandleFunc func(context.Context, TokenExchangeRequest) (TokenExchangeResult, error)

type Actor struct {
	Subject string `json:"sub,omitempty"`
	Issuer  string `json:"iss,omitempty"`
	Actor   *Actor `json:"act,omitempty"`
}
