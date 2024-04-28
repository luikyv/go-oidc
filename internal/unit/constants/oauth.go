package constants

import (
	"net/http"
	"strings"
)

type GrantType string

const (
	ClientCredentialsGrant GrantType = "client_credentials"
	AuthorizationCodeGrant GrantType = "authorization_code"
	RefreshTokenGrant      GrantType = "refresh_token"
	ImplictGrant           GrantType = "implict"
)

var GrantTypes []GrantType = []GrantType{
	ClientCredentialsGrant,
	AuthorizationCodeGrant,
	RefreshTokenGrant,
	ImplictGrant,
}

type ResponseType string

func (rt ResponseType) Contains(responseType ResponseType) bool {
	for _, s := range strings.Split(string(rt), " ") {
		if s == string(responseType) {
			return true
		}
	}
	return false
}

func (rt ResponseType) IsImplict() bool {
	return rt.Contains(IdTokenResponse) || rt.Contains(TokenResponseResponse)
}

const (
	CodeResponse                   ResponseType = "code"
	IdTokenResponse                ResponseType = "id_token"
	TokenResponseResponse          ResponseType = "token"
	CodeAndIdTokenResponse         ResponseType = "code id_token"
	CodeAndTokenResponse           ResponseType = "code token"
	IdTokenAndTokenResponse        ResponseType = "id_token token"
	CodeAndIdTokenAndTokenResponse ResponseType = "code id_token token"
)

var ResponseTypes []ResponseType = []ResponseType{
	CodeResponse,
	IdTokenResponse,
	TokenResponseResponse,
	CodeAndIdTokenResponse,
	CodeAndTokenResponse,
	IdTokenAndTokenResponse,
	CodeAndIdTokenAndTokenResponse,
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

var ResponseModes []ResponseMode = []ResponseMode{
	QueryResponseMode,
	FragmentResponseMode,
	FormPostResponseMode,
	QueryJwtResponseMode,
	FragmentJwtResponseMode,
	FormPostJwtResponseMode,
	JwtResponseMode,
}

type ClientAuthnType string

const (
	NoneAuthn              ClientAuthnType = "none"
	ClientSecretBasicAuthn ClientAuthnType = "client_secret_basic"
	ClientSecretPostAuthn  ClientAuthnType = "client_secret_post"
	PrivateKeyJwtAuthn     ClientAuthnType = "private_key_jwt"
)

var ClientAuthnTypes []ClientAuthnType = []ClientAuthnType{
	NoneAuthn,
	ClientSecretBasicAuthn,
	ClientSecretPostAuthn,
	PrivateKeyJwtAuthn,
}

type ClientAssertionType string

const (
	JWTBearerAssertion ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type TokenType string

const (
	Bearer TokenType = "Bearer"
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

type CodeChallengeMethod string

const (
	SHA256CodeChallengeMethod CodeChallengeMethod = "S256"
	PlainCodeChallengeMethod  CodeChallengeMethod = "plain"
)

var CodeChallengeMethods []CodeChallengeMethod = []CodeChallengeMethod{
	SHA256CodeChallengeMethod,
	PlainCodeChallengeMethod,
}

// For more information, see: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
type SubjectIdentifierType string

const (
	// The OP provides the same sub (subject) value to all Clients.
	PublicSubjectIdentifier SubjectIdentifierType = "public"
)

var SubjectIdentifierTypes []SubjectIdentifierType = []SubjectIdentifierType{
	PublicSubjectIdentifier,
}

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

const CorrelationIdHeader Header = "X-Correlation-ID"

const OpenIdScope string = "openid"
