package models

import (
	"slices"

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

type SecretClientAuthenticator struct {
	HashedSecret string
}

func (authenticator SecretClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {

	err := bcrypt.CompareHashAndPassword([]byte(authenticator.HashedSecret), []byte(req.ClientSecret))
	return err == nil
}

type PrivateKeyJwtClientAuthenticator struct {
	PublicJwk jose.JSONWebKey
}

func (authenticator PrivateKeyJwtClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {

	jwt, err := jwt.ParseSigned(req.ClientAssertion, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(authenticator.PublicJwk.Algorithm)})
	if err != nil {
		return false
	}

	claims := make(map[string]interface{})
	if err := jwt.Claims(authenticator.PublicJwk.Key, &claims); err != nil {
		return false
	}

	if issuer, ok := claims["iss"]; !ok || issuer != req.ClientId {
		return false
	}
	if subject, ok := claims["sub"]; !ok || subject != req.ClientId {
		return false
	}
	// TODO: validate the audience as the oauth server.

	return true
}

//---------------------------------------- Client ----------------------------------------//

type ClientOut struct{}

type Client struct {
	Id                  string
	RedirectUris        []string
	ResponseTypes       []constants.ResponseType
	GrantTypes          []constants.GrantType
	Scopes              []string
	PkceIsRequired      bool
	DefaultTokenModelId string
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
