package models

import (
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

//---------------------------------------- Client Authentication ----------------------------------------//

type ClientAuthenticator interface {
	IsAuthenticated(req ClientAuthnRequest) bool
	GetAuthnType() constants.ClientAuthnType
}

type NoneClientAuthenticator struct{}

func (authenticator NoneClientAuthenticator) GetAuthnType() constants.ClientAuthnType {
	return constants.NoneAuthn
}

func (authenticator NoneClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {
	return true
}

type SecretBasicClientAuthenticator struct {
	Salt         string
	HashedSecret string
}

func (authenticator SecretBasicClientAuthenticator) GetAuthnType() constants.ClientAuthnType {
	return constants.ClientSecretBasicAuthn
}

func (authenticator SecretBasicClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {

	saltedSecret := authenticator.Salt + req.ClientSecretBasicAuthn
	err := bcrypt.CompareHashAndPassword([]byte(authenticator.HashedSecret), []byte(saltedSecret))
	return err == nil
}

type SecretPostClientAuthenticator struct {
	Salt         string
	HashedSecret string
}

func (authenticator SecretPostClientAuthenticator) GetAuthnType() constants.ClientAuthnType {
	return constants.ClientSecretPostAuthn
}

func (authenticator SecretPostClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {

	saltedSecret := authenticator.Salt + req.ClientSecretPost
	err := bcrypt.CompareHashAndPassword([]byte(authenticator.HashedSecret), []byte(saltedSecret))
	return err == nil
}

type PrivateKeyJwtClientAuthenticator struct {
	PublicJwks               jose.JSONWebKeySet
	Host                     string
	MaxAssertionLifetimeSecs int
}

func (authenticator PrivateKeyJwtClientAuthenticator) GetAuthnType() constants.ClientAuthnType {
	return constants.PrivateKeyJwtAuthn
}

func (authenticator PrivateKeyJwtClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {

	assertion, err := jwt.ParseSigned(req.ClientAssertion, authenticator.GetSigningAlgorithms())
	if err != nil {
		return false
	}

	// Verify that the assertion indicates the key ID.
	if len(assertion.Headers) != 1 && assertion.Headers[0].KeyID == "" {
		return false
	}

	// Verify that the key ID belongs to the client.
	keys := authenticator.PublicJwks.Key(assertion.Headers[0].KeyID)
	if len(keys) == 0 {
		return false
	}

	jwk := keys[0]
	claims := jwt.Claims{}
	if err := assertion.Claims(jwk.Key, &claims); err != nil {
		return false
	}

	// Validate that the "iat" and "exp" claims are present and their difference is not too great.
	if claims.Expiry == nil || claims.IssuedAt == nil || int(claims.Expiry.Time().Sub(claims.IssuedAt.Time()).Seconds()) > authenticator.MaxAssertionLifetimeSecs {
		return false
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      claims.Subject,
		Subject:     claims.Subject,
		AnyAudience: []string{authenticator.Host, authenticator.Host + string(constants.TokenEndpoint), authenticator.Host + string(constants.PushedAuthorizationRequestEndpoint)},
	}, time.Duration(0))
	return err == nil
}

func (authenticator PrivateKeyJwtClientAuthenticator) GetSigningAlgorithms() []jose.SignatureAlgorithm {

	return getSigningAlgorithms(authenticator.PublicJwks)
}

//---------------------------------------- Client ----------------------------------------//

type ClientOut struct{}

type Client struct {
	Id                  string
	RedirectUris        []string
	ResponseTypes       []constants.ResponseType
	ResponseModes       []constants.ResponseMode
	GrantTypes          []constants.GrantType
	Scopes              []string
	PkceIsRequired      bool
	DefaultGrantModelId string
	PublicJwks          jose.JSONWebKeySet
	Attributes          map[string]string
	Authenticator       ClientAuthenticator
}

func (client Client) ToOutput() ClientOut {
	return ClientOut{}
}

func (client Client) AreScopesAllowed(requestedScopes []string) bool {
	return unit.ContainsAll(client.Scopes, requestedScopes)
}

func (client Client) IsResponseTypeAllowed(responseType constants.ResponseType) bool {
	return slices.Contains(client.ResponseTypes, responseType)
}

func (client Client) IsResponseModeAllowed(responseMode constants.ResponseMode) bool {
	return slices.Contains(client.ResponseModes, responseMode)
}

func (client Client) IsGrantTypeAllowed(grantType constants.GrantType) bool {
	return slices.Contains(client.GrantTypes, grantType)
}

func (client Client) IsRedirectUriAllowed(redirectUri string) bool {
	for _, ru := range client.RedirectUris {
		if strings.HasPrefix(redirectUri, ru) {
			return true
		}
	}
	return false
}

func (client Client) GetSigningAlgorithms() []jose.SignatureAlgorithm {
	return getSigningAlgorithms(client.PublicJwks)
}

type ClientIn struct{}

func (client ClientIn) ToInternal() Client {
	return Client{}
}

func getSigningAlgorithms(jwks jose.JSONWebKeySet) []jose.SignatureAlgorithm {
	signingAlgorithms := []jose.SignatureAlgorithm{}
	for _, jwk := range jwks.Keys {
		signingAlgorithms = append(signingAlgorithms, jose.SignatureAlgorithm(jwk.Algorithm))
	}
	return signingAlgorithms
}
