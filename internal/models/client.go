package models

import (
	"slices"

	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

//---------------------------------------- Client Authentication ----------------------------------------//

type ClientAuthenticator interface {
	IsAuthenticated(ctx ClientAuthnContext) bool
}

type NoneClientAuthenticator struct{}

func (authenticator NoneClientAuthenticator) IsAuthenticated(ctx ClientAuthnContext) bool {
	return ctx.ClientSecret == ""
}

type SecretClientAuthenticator struct {
	HashedSecret string
}

func (authenticator SecretClientAuthenticator) IsAuthenticated(ctx ClientAuthnContext) bool {
	err := bcrypt.CompareHashAndPassword([]byte(authenticator.HashedSecret), []byte(ctx.ClientSecret))
	return err == nil
}

//---------------------------------------- Client ----------------------------------------//

type ClientOut struct{}

type Client struct {
	Id                  string
	RedirectUris        []string
	ResponseTypes       []constants.ResponseType
	GrantTypes          []constants.GrantType
	Scopes              []string
	PkceIsRequired      string
	DefaultTokenModelId string
	ExtraParams         map[string]string
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
