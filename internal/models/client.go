package models

import (
	"slices"
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
}

type NoneClientAuthenticator struct{}

func (authenticator NoneClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {
	return true
}

type SecretBasicClientAuthenticator struct {
	Salt         string
	HashedSecret string
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

func (authenticator SecretPostClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {

	saltedSecret := authenticator.Salt + req.ClientSecretPost
	err := bcrypt.CompareHashAndPassword([]byte(authenticator.HashedSecret), []byte(saltedSecret))
	return err == nil
}

type PrivateKeyJwtClientAuthenticator struct {
	PublicJwk jose.JSONWebKey
}

func (authenticator PrivateKeyJwtClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {
	// TODO: validate the audience as the oauth server.
	// TODO: Do I need to validate the "kid" header to make sure is the same in the client's JWK?

	assertion, err := jwt.ParseSigned(req.ClientAssertion, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(authenticator.PublicJwk.Algorithm)})
	if err != nil {
		return false
	}

	claims := jwt.Claims{}
	if err := assertion.Claims(authenticator.PublicJwk.Key, &claims); err != nil {
		return false
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:  claims.Subject,
		Subject: claims.Subject,
	}, time.Duration(0))
	return err == nil
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
	Attributes          map[string]string
	Authenticator       ClientAuthenticator
}

func (client Client) ToOutput() ClientOut {
	return ClientOut{}
}

func (client Client) AreScopesAllowed(requestedScopes []string) bool {
	return unit.Contains(client.Scopes, requestedScopes)
}

func (client Client) AreResponseTypesAllowed(responseTypes []string) bool {
	for _, responseType := range responseTypes {
		if !client.isResponseTypeAllowed(constants.ResponseType(responseType)) {
			return false
		}
	}

	return true
}

func (client Client) isResponseTypeAllowed(responseType constants.ResponseType) bool {
	return slices.Contains(client.ResponseTypes, responseType)
}

func (client Client) IsResponseModeAllowed(responseMode constants.ResponseMode) bool {
	return slices.Contains(client.ResponseModes, responseMode)
}

func (client Client) IsGrantTypeAllowed(grantType constants.GrantType) bool {
	return slices.Contains(client.GrantTypes, grantType)
}

func (client Client) IsRedirectUriAllowed(redirectUri string) bool {
	return slices.Contains(client.RedirectUris, redirectUri)
}

type ClientIn struct{}

func (client ClientIn) ToInternal() Client {
	return Client{}
}
