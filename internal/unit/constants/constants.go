package constants

import (
	"net/http"
	"slices"
	"strings"
)

type GrantType string

const (
	ClientCredentialsGrant GrantType = "client_credentials"
	AuthorizationCodeGrant GrantType = "authorization_code"
	RefreshTokenGrant      GrantType = "refresh_token"
	ImplicitGrant          GrantType = "implicit"
)

type ResponseType string

const (
	CodeResponse                   ResponseType = "code"
	IdTokenResponse                ResponseType = "id_token"
	TokenResponse                  ResponseType = "token"
	CodeAndIdTokenResponse         ResponseType = "code id_token"
	CodeAndTokenResponse           ResponseType = "code token"
	IdTokenAndTokenResponse        ResponseType = "id_token token"
	CodeAndIdTokenAndTokenResponse ResponseType = "code id_token token"
)

func (rt ResponseType) Contains(responseType ResponseType) bool {
	return slices.Contains(strings.Split(string(rt), " "), string(responseType))
}

func (rt ResponseType) IsImplicit() bool {
	return rt.Contains(IdTokenResponse) || rt.Contains(TokenResponse)
}

type ResponseMode string

const (
	QueryResponseMode    ResponseMode = "query"
	FragmentResponseMode ResponseMode = "fragment"
	FormPostResponseMode ResponseMode = "form_post"
	// JWT Secured Authorization Response Modes.
	// For more information, see https://openid.net/specs/oauth-v2-jarm.html.
	QueryJwtResponseMode    ResponseMode = "query.jwt"
	FragmentJwtResponseMode ResponseMode = "fragment.jwt"
	FormPostJwtResponseMode ResponseMode = "form_post.jwt"
	JwtResponseMode         ResponseMode = "jwt"
)

func (rm ResponseMode) IsJarm() bool {
	return strings.HasSuffix(string(rm), string(JwtResponseMode))
}

func (rm ResponseMode) IsQuery() bool {
	return strings.HasPrefix(string(rm), string(QueryResponseMode))
}

type ClientAuthnType string

const (
	NoneAuthn              ClientAuthnType = "none"
	ClientSecretBasicAuthn ClientAuthnType = "client_secret_basic"
	ClientSecretPostAuthn  ClientAuthnType = "client_secret_post"
	ClientSecretJwt        ClientAuthnType = "client_secret_jwt"
	PrivateKeyJwtAuthn     ClientAuthnType = "private_key_jwt"
)

type ClientAssertionType string

const (
	JwtBearerAssertion ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type TokenType string

const (
	BearerTokenType TokenType = "Bearer"
	DpopTokenType   TokenType = "DPoP"
)

type Claim string

const (
	TokenIdClaim               Claim = "jti"
	IssuerClaim                Claim = "iss"
	SubjectClaim               Claim = "sub"
	AudienceClaim              Claim = "aud"
	ExpiryClaim                Claim = "exp"
	IssuedAtClaim              Claim = "iat"
	ScopeClaim                 Claim = "scope"
	NonceClaim                 Claim = "nonce"
	AccessTokenHashClaim       Claim = "at_hash"
	AuthorizationCodeHashClaim Claim = "c_hash"
	StateHashClaim             Claim = "s_hash"
)

type KeyUsage string

const (
	KeySignatureUsage KeyUsage = "sig"
)

type CodeChallengeMethod string

const (
	Sha256CodeChallengeMethod CodeChallengeMethod = "S256"
	PlainCodeChallengeMethod  CodeChallengeMethod = "plain"
)

// For more information, see: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
type SubjectIdentifierType string

const (
	// The OP provides the same sub (subject) value to all Clients.
	PublicSubjectIdentifier SubjectIdentifierType = "public"
)

type ErrorCode string

const (
	AccessDenied         ErrorCode = "access_denied"
	InvalidClient        ErrorCode = "invalid_client"
	InvalidGrant         ErrorCode = "invalid_grant"
	InvalidRequest       ErrorCode = "invalid_request"
	UnauthorizedClient   ErrorCode = "unauthorized_client"
	InvalidScope         ErrorCode = "invalid_scope"
	UnsupportedGrantType ErrorCode = "unsupported_grant_type"
	InternalError        ErrorCode = "internal_error"
)

var ErrorCodeToStatusCode map[ErrorCode]int = map[ErrorCode]int{
	AccessDenied:         http.StatusForbidden,
	InvalidClient:        http.StatusUnauthorized,
	InvalidGrant:         http.StatusBadRequest,
	InvalidRequest:       http.StatusBadRequest,
	UnauthorizedClient:   http.StatusBadRequest,
	InvalidScope:         http.StatusBadRequest,
	UnsupportedGrantType: http.StatusBadRequest,
	InternalError:        http.StatusInternalServerError,
}

type Header string

const (
	CorrelationIdHeader Header = "X-Correlation-ID"
	DpopHeader          Header = "DPoP"
)

const OpenIdScope string = "openid"

const CallbackIdLength int = 20

const RequestUriLength int = 20

const AuthorizationCodeLifetimeSecs int = 60

const AuthorizationCodeLength int = 30

const RefreshTokenLength int = 30

const DynamicClientIdLength int = 30

const ClientSecretLength int = 50

const RegistrationAccessTokenLength int = 50

const DefaultTokenLifetimeSecs int = 300

const DefaultRefreshTokenLifetimeSecs int = 6000

type Profile string

const (
	OpenIdProfile Profile = "oidc_profile"
)

const Charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type AuthnStatus string

const (
	Success    AuthnStatus = "success"
	InProgress AuthnStatus = "in_progress"
	Failure    AuthnStatus = "failure"
)

const CorrelationIdKey string = "correlation_id"

type TokenFormat string

const (
	JwtTokenFormat    TokenFormat = "jwt"
	OpaqueTokenFormat TokenFormat = "opaque"
)

type EndpointPath string

const (
	WellKnownEndpoint                  EndpointPath = "/.well-known/openid-configuration"
	JsonWebKeySetEndpoint              EndpointPath = "/jwks"
	PushedAuthorizationRequestEndpoint EndpointPath = "/par"
	AuthorizationEndpoint              EndpointPath = "/authorize"
	TokenEndpoint                      EndpointPath = "/token"
	UserInfoEndpoint                   EndpointPath = "/userinfo"
	DynamicClientEndpoint              EndpointPath = "/register"
)
