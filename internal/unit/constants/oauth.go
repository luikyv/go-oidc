package constants

import (
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

type GrantType string

const (
	ClientCredentials GrantType = "client_credentials"
	AuthorizationCode GrantType = "authorization_code"
	RefreshToken      GrantType = "refresh_token"
	Implict           GrantType = "implict"
)

var GrantTypes []GrantType = []GrantType{
	ClientCredentials,
	AuthorizationCode,
	RefreshToken,
	Implict,
}

type ResponseType string

const (
	Code           ResponseType = "code"
	IdToken        ResponseType = "id_token"
	CodeAndIdToken ResponseType = "code id_token"
)

var ResponseTypes []ResponseType = []ResponseType{
	Code,
	IdToken,
	CodeAndIdToken,
}

type ResponseMode string

const (
	Query    ResponseMode = "query"
	Fragment ResponseMode = "fragment"
	FormPost ResponseMode = "form_post"
)

var ResponseModes []ResponseMode = []ResponseMode{
	Query,
	Fragment,
	FormPost,
}

type ClientAuthnType string

const (
	None              ClientAuthnType = "none"
	ClientSecretBasic ClientAuthnType = "client_secret_basic"
	ClientSecretPost  ClientAuthnType = "client_secret_post"
	PrivateKeyJWT     ClientAuthnType = "private_key_jwt"
)

var ClientAuthnTypes []ClientAuthnType = []ClientAuthnType{
	None,
	ClientSecretBasic,
	ClientSecretPost,
	PrivateKeyJWT,
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
	TokenId  Claim = "jti"
	Issuer   Claim = "iss"
	Subject  Claim = "sub"
	Audience Claim = "aud"
	Expiry   Claim = "exp"
	IssuedAt Claim = "iat"
	Scope    Claim = "scope"
	Nonce    Claim = "nonce"
)

type CodeChallengeMethod string

const (
	SHA256 CodeChallengeMethod = "S256"
	Plain  CodeChallengeMethod = "plain"
)

var CodeChallengeMethods []CodeChallengeMethod = []CodeChallengeMethod{
	SHA256,
	Plain,
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

var PrivateJWKS jose.JSONWebKeySet

const OpenIdScope string = "openid"
