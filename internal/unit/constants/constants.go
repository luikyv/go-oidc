package constants

import (
	"crypto/tls"
	"net/http"
	"slices"
	"strings"
)

type ContextKey string

const CorrelationIdKey ContextKey = "correlation_id"

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
	// JARM - JWT Secured Authorization Response Mode.
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
	JwtBearerAssertionType ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type TokenType string

const (
	BearerTokenType TokenType = "Bearer"
	DpopTokenType   TokenType = "DPoP"
)

const (
	TokenIdClaim                        string = "jti"
	IssuerClaim                         string = "iss"
	SubjectClaim                        string = "sub"
	AudienceClaim                       string = "aud"
	ClientIdClaim                       string = "client_id"
	ExpiryClaim                         string = "exp"
	IssuedAtClaim                       string = "iat"
	ScopeClaim                          string = "scope"
	NonceClaim                          string = "nonce"
	AuthenticationTimeClaim             string = "auth_time"
	AuthenticationMethodReferencesClaim string = "amr"
	AuthenticationContextReferenceClaim string = "acr"
	ProfileClaim                        string = "profile"
	EmailClaim                          string = "email"
	EmailVerifiedClaim                  string = "email_verified"
	AddressClaim                        string = "address"
	AccessTokenHashClaim                string = "at_hash"
	AuthorizationCodeHashClaim          string = "c_hash"
	StateHashClaim                      string = "s_hash"
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
	case InvalidClient, InvalidToken, UnauthorizedClient:
		return http.StatusUnauthorized
	case InternalError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

const (
	CorrelationIdHeader             string = "X-Correlation-Id"
	FapiInteractionIdHeader         string = "X-Fapi-Interaction-Id"
	DpopHeader                      string = "DPoP"
	ClientCertificateHeader         string = "X-Client-Certificate"
	SecureClientCertificateHeader   string = "X-Secure-Client-Certificate"
	InsecureClientCertificateHeader string = "X-Insecure-Client-Certificate"
)

const (
	OpenIdScope         string = "openid"
	ProfileScope        string = "profile"
	EmailScope          string = "email"
	AddressScope        string = "address"
	OffilineAccessScope string = "offline_access"
)

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
	Fapi2Profile  Profile = "fapi2_profile"
)

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

type DisplayValue string

const (
	PageDisplay  DisplayValue = "page"
	PopUpDisplay DisplayValue = "popup"
	TouchDisplay DisplayValue = "touch"
	WatDisplay   DisplayValue = "wap"
)

type PromptType string

const (
	NonePromptType          PromptType = "none"
	LoginPromptType         PromptType = "login"
	ConsentPromptType       PromptType = "consent"
	SelectAccountPromptType PromptType = "select_account"
)

type ClaimType string

const (
	NormalClaimType      ClaimType = "normal"
	AggregatedClaimType  ClaimType = "aggregated"
	DistributedClaimType ClaimType = "distributed"
)

type TokenTypeHint string

const (
	AccessTokenHint  TokenTypeHint = "access_token"
	RefreshTokenHint TokenTypeHint = "refresh_token"
)

type AuthenticationContextReference string

const (
	NoAssuranceLevelAcr AuthenticationContextReference = "0"
)

var FapiAllowedCipherSuites []uint16 = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}
