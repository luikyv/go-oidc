package models

import (
	"slices"

	"github.com/golang-jwt/jwt/v5"
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
	return req.ClientSecret == "" && req.ClientAssertionType == "" && req.ClientAssertion == ""
}

type SecretClientAuthenticator struct {
	HashedSecret string
}

func (authenticator SecretClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {
	if req.ClientSecret == "" || req.ClientAssertionType != "" || req.ClientAssertion != "" {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(authenticator.HashedSecret), []byte(req.ClientSecret))
	return err == nil
}

type PrivateKeyJwtClientAuthenticator struct {
	PublicJwk JWK
}

func (authenticator PrivateKeyJwtClientAuthenticator) IsAuthenticated(req ClientAuthnRequest) bool {
	if req.ClientSecret != "" || req.ClientAssertionType != constants.JWTBearer || req.ClientAssertion == "" {
		return false
	}

	var claims jwt.MapClaims
	jwtToken, err := jwt.ParseWithClaims(req.ClientAssertion, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(authenticator.PublicJwk.Key), nil
	})

	if err != nil || !jwtToken.Valid || jwtToken.Method.Alg() != string(authenticator.PublicJwk.SigningAlgorithm) {
		return false
	}

	if issuer, err := claims.GetIssuer(); err != nil || issuer != req.ClientId {
		return false
	}
	if subject, err := claims.GetSubject(); err != nil || subject != req.ClientId {
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
