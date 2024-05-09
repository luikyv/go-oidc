package constants

import (
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
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

const (
	CodeResponse                   ResponseType = "code"
	IdTokenResponse                ResponseType = "id_token"
	TokenResponse                  ResponseType = "token"
	CodeAndIdTokenResponse         ResponseType = "code id_token"
	CodeAndTokenResponse           ResponseType = "code token"
	IdTokenAndTokenResponse        ResponseType = "id_token token"
	CodeAndIdTokenAndTokenResponse ResponseType = "code id_token token"
)

var ResponseTypes []ResponseType = []ResponseType{
	CodeResponse,
	IdTokenResponse,
	TokenResponse,
	CodeAndIdTokenResponse,
	CodeAndTokenResponse,
	IdTokenAndTokenResponse,
	CodeAndIdTokenAndTokenResponse,
}

var OAuthCoreResponseTypes []ResponseType = []ResponseType{
	CodeResponse,
	TokenResponse,
	CodeAndTokenResponse,
}

func (rt ResponseType) Contains(responseType ResponseType) bool {
	for _, s := range strings.Split(string(rt), " ") {
		if s == string(responseType) {
			return true
		}
	}
	return false
}

func (rt ResponseType) IsValid() bool {
	return slices.Contains(ResponseTypes, rt)
}

func (rt ResponseType) IsOAuthCoreValid() bool {
	return slices.Contains(OAuthCoreResponseTypes, rt)
}

func (rt ResponseType) IsImplict() bool {
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

var ResponseModes []ResponseMode = []ResponseMode{
	QueryResponseMode,
	FragmentResponseMode,
	FormPostResponseMode,
	QueryJwtResponseMode,
	FragmentJwtResponseMode,
	FormPostJwtResponseMode,
	JwtResponseMode,
}

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
	BearerToken TokenType = "Bearer"
	DpopToken   TokenType = "DPoP"
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
	KeySigningUsage KeyUsage = "sig"
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

func (ccm CodeChallengeMethod) IsValid() bool {
	return slices.Contains(CodeChallengeMethods, ccm)
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

var DpopSigningAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.ES256,
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

const (
	CorrelationIdHeader Header = "X-Correlation-ID"
	DpopHeader          Header = "DPoP"
)

const OpenIdScope string = "openid"
