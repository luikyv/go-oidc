package constants

import (
	"crypto/tls"
	"net/http"
	"slices"
	"strings"
)

type ContextKey string

const CorrelationId ContextKey = "correlation_id"

const ProtectedParamPrefix string = "p_"

type GrantType string

const (
	ClientCredentialsGrant GrantType = "client_credentials"
	AuthorizationCodeGrant GrantType = "authorization_code"
	RefreshTokenGrant      GrantType = "refresh_token"
	ImplicitGrant          GrantType = "implicit"
	IntrospectionGrant     GrantType = "urn:goidc:oauth2:grant_type:token_intropection"
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
	TlsAuthn               ClientAuthnType = "tls_client_auth"
	SelfSignedTlsAuthn     ClientAuthnType = "self_signed_tls_client_auth"
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
	TokenIdClaim                        Claim = "jti"
	IssuerClaim                         Claim = "iss"
	SubjectClaim                        Claim = "sub"
	AudienceClaim                       Claim = "aud"
	ClientIdClaim                       Claim = "client_id"
	ExpiryClaim                         Claim = "exp"
	IssuedAtClaim                       Claim = "iat"
	ScopeClaim                          Claim = "scope"
	NonceClaim                          Claim = "nonce"
	AuthenticationTimeClaim             Claim = "auth_time"
	AuthenticationMethodReferencesClaim Claim = "amr"
	AccessTokenHashClaim                Claim = "at_hash"
	AuthorizationCodeHashClaim          Claim = "c_hash"
	StateHashClaim                      Claim = "s_hash"
)

var Claims = []Claim{
	TokenIdClaim,
	IssuerClaim,
	SubjectClaim,
	AudienceClaim,
	ClientIdClaim,
	ExpiryClaim,
	IssuedAtClaim,
	ScopeClaim,
	NonceClaim,
	AuthenticationTimeClaim,
	AuthenticationMethodReferencesClaim,
	AccessTokenHashClaim,
	AuthorizationCodeHashClaim,
	StateHashClaim,
}

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
	AccessDenied          ErrorCode = "access_denied"
	InvalidClient         ErrorCode = "invalid_client"
	InvalidGrant          ErrorCode = "invalid_grant"
	InvalidRequest        ErrorCode = "invalid_request"
	UnauthorizedClient    ErrorCode = "unauthorized_client"
	InvalidScope          ErrorCode = "invalid_scope"
	UnsupportedGrantType  ErrorCode = "unsupported_grant_type"
	InvalidResquestObject ErrorCode = "invalid_request_object"
	InvalidToken          ErrorCode = "invalid_token"
	InternalError         ErrorCode = "internal_error"
)

func (ec ErrorCode) GetStatusCode() int {
	switch ec {
	case AccessDenied:
		return http.StatusForbidden
	case InvalidClient, InvalidToken:
		return http.StatusUnauthorized
	case InternalError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

type Header string

const (
	CorrelationIdHeader     Header = "X-Correlation-Id"
	FapiInteractionIdHeader Header = "X-Fapi-Interaction-Id"
	DpopHeader              Header = "DPoP"
	ClientCertificateHeader Header = "X-Client-Certificate"
)

const OpenIdScope string = "openid"

const DefaultAuthenticationSessionTimeoutSecs = 30 * 60

const CallbackIdLength int = 20

const RequestUriLength int = 20

const AuthorizationCodeLifetimeSecs int = 60

const AuthorizationCodeLength int = 30

// During introspection, a refresh token is identified by its length.
// Then, setting the length to an unusual value will avoid refresh tokens
// and opaque access token to be confused.
const RefreshTokenLength int = 99

const DefaultRefreshTokenLifetimeSecs int = 6000

const DynamicClientIdLength int = 30

const ClientSecretLength int = 50

const RegistrationAccessTokenLength int = 50

const DefaultTokenLifetimeSecs int = 300

type Profile string

const (
	OpenIdProfile Profile = "oidc_profile"
	Fapi1Profile  Profile = "fapi1_profile"
	Fapi2Profile  Profile = "fapi2_profile"
)

func (p Profile) IsFapi() bool {
	return p == Fapi1Profile || p == Fapi2Profile
}

const Charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type AuthnStatus string

const (
	Success    AuthnStatus = "success"
	InProgress AuthnStatus = "in_progress"
	Failure    AuthnStatus = "failure"
)

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
	TokenIntrospectionEndpoint         EndpointPath = "/introspect"
)

// RFC8176.
type AuthenticationMethodReference string

const (
	FacialRecognitionAuthentication            AuthenticationMethodReference = "face"
	FingerPrintAuthentication                  AuthenticationMethodReference = "fpt"
	GeolocationAuthentication                  AuthenticationMethodReference = "geo"
	HardwareSecuredKeyAuthentication           AuthenticationMethodReference = "hwk"
	IrisScanAuthentication                     AuthenticationMethodReference = "iris"
	MultipleFactorAuthentication               AuthenticationMethodReference = "mfa"
	OneTimePassowordAuthentication             AuthenticationMethodReference = "otp"
	PasswordAuthentication                     AuthenticationMethodReference = "pwd"
	PersonalIdentificationNumberAuthentication AuthenticationMethodReference = "pin"
	RiskBasedAuthentication                    AuthenticationMethodReference = "rba"
	SmsAuthentication                          AuthenticationMethodReference = "sms"
	SoftwareSecuredKeyAuthentication           AuthenticationMethodReference = "swk"
)

type PromptType string

const (
	NonePromptType          PromptType = "none"
	LoginPromptType         PromptType = "login"
	ConsentPromptType       PromptType = "consent"
	SelectAccountPromptType PromptType = "select_account"
)

type TokenTypeHint string

const (
	AccessTokenHint  TokenTypeHint = "access_token"
	RefreshTokenHint TokenTypeHint = "refresh_token"
)

var FapiAllowedCipherSuites []uint16 = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}
