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

type ResponseType string

const (
	Code    ResponseType = "code"
	IdToken ResponseType = "id_token"
)

type ClientAuthnType string

const (
	None          ClientAuthnType = "none"
	ClientSecret  ClientAuthnType = "client_secret"
	PrivateKeyJWT ClientAuthnType = "private_key_jwt"
)

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

type ErrorCode string

const (
	AccessDenied   ErrorCode = "access_denied"
	InvalidRequest ErrorCode = "invalid_request"
	InvalidScope   ErrorCode = "invalid_scope"
)

var ErrorCodeToStatusCode map[ErrorCode]int = map[ErrorCode]int{
	AccessDenied:   http.StatusForbidden,
	InvalidRequest: http.StatusBadRequest,
	InvalidScope:   http.StatusBadRequest,
}

type Header string

const CorrelationIdHeader Header = "X-Correlation-ID"

var PrivateJWKS jose.JSONWebKeySet

const OpenIdScope string = "openid"
