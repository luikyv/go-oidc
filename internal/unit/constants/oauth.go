package constants

import (
	"net/http"
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

func (rt ResponseType) Contains(responseType ResponseType) bool {
	for _, s := range strings.Split(string(rt), " ") {
		if s == string(responseType) {
			return true
		}
	}
	return false
}

const (
	CodeResponse                   ResponseType = "code"
	IdTokenResponse                ResponseType = "id_token"
	TokenResponse                  ResponseType = "token"
	CodeAndIdTokenResponse         ResponseType = "code id_token"
	CodeAndToken                   ResponseType = "code token"
	IdTokenAndToken                ResponseType = "id_token token"
	CodeAndIdTokenAndTokenResponse ResponseType = "code id_token token"
)

var ResponseTypes []ResponseType = []ResponseType{
	CodeResponse,
	IdTokenResponse,
	TokenResponse,
	CodeAndIdTokenResponse,
	CodeAndToken,
	IdTokenAndToken,
	CodeAndIdTokenAndTokenResponse,
}

type ResponseMode string

const (
	QueryResponseMode    ResponseMode = "query"
	FragmentResponseMode ResponseMode = "fragment"
	FormPostResponseMode ResponseMode = "form_post"
)

var ResponseModes []ResponseMode = []ResponseMode{
	QueryResponseMode,
	FragmentResponseMode,
	FormPostResponseMode,
}

type ClientAuthnType string

const (
	NoneAuthn              ClientAuthnType = "none"
	ClientSecretBasicAuthn ClientAuthnType = "client_secret_basic"
	ClientSecretPostAuthn  ClientAuthnType = "client_secret_post"
	PrivateKeyJWTAuthn     ClientAuthnType = "private_key_jwt"
)

var ClientAuthnTypes []ClientAuthnType = []ClientAuthnType{
	NoneAuthn,
	ClientSecretBasicAuthn,
	ClientSecretPostAuthn,
	PrivateKeyJWTAuthn,
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

// TODO It could be in the context.
var PrivateJWKS jose.JSONWebKeySet

const OpenIdScope string = "openid"
