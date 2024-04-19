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
)

var GrantTypes []GrantType = []GrantType{
	ClientCredentials,
	AuthorizationCode,
	RefreshToken,
}

type ResponseType string

const (
	Code    ResponseType = "code"
	IdToken ResponseType = "id_token"
)

var ResponseTypes []ResponseType = []ResponseType{
	Code,
	IdToken,
}

// TODO: Implement the response modes.
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

type ErrorCode string

const (
	AccessDenied   ErrorCode = "access_denied"
	InvalidGrant   ErrorCode = "invalid_grant"
	InvalidRequest ErrorCode = "invalid_request"
	InvalidScope   ErrorCode = "invalid_scope"
	InternalError  ErrorCode = "internal_error"
)

var ErrorCodeToStatusCode map[ErrorCode]int = map[ErrorCode]int{
	AccessDenied:   http.StatusForbidden,
	InvalidGrant:   http.StatusBadRequest,
	InvalidRequest: http.StatusBadRequest,
	InvalidScope:   http.StatusBadRequest,
}

type Header string

const CorrelationIdHeader Header = "X-Correlation-ID"

var PrivateJWKS jose.JSONWebKeySet

const OpenIdScope string = "openid"
