package models

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"golang.org/x/crypto/bcrypt"
)

const (
	TestClientId           string = "random_client_id"
	TestClientSecret       string = "random_client_secret"
	TestOpaqueGrantModelId string = "opaque_grant_model_id"
	TestJwtGrantModelId    string = "jwt_grant_model_id"
)

func GetTestClientWithBasicAuthn() Client {
	clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(TestClientSecret), 0)
	client := GetTestClientWithNoneAuthn()
	client.AuthnMethod = constants.ClientSecretPostAuthn
	client.HashedSecret = string(clientHashedSecret)
	return client
}

func GetTestClientWithSecretPostAuthn() Client {
	clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(TestClientSecret), 0)
	client := GetTestClientWithNoneAuthn()
	client.AuthnMethod = constants.ClientSecretPostAuthn
	client.HashedSecret = string(clientHashedSecret)
	return client
}

func GetTestClientWithPrivateKeyJwtAuthn(host string, publicJwk jose.JSONWebKey) Client {
	client := GetTestClientWithNoneAuthn()
	client.AuthnMethod = constants.PrivateKeyJwtAuthn
	client.PublicJwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJwk}}
	return client
}

func GetTestClientWithNoneAuthn() Client {
	return Client{
		Id: TestClientId,
		ClientMetaInfo: ClientMetaInfo{
			AuthnMethod:  constants.NoneAuthn,
			RedirectUris: []string{"https://example.com"},
			Scopes:       "scope1 scope2 " + constants.OpenIdScope,
			GrantTypes: []constants.GrantType{
				constants.AuthorizationCodeGrant,
				constants.ClientCredentialsGrant,
				constants.ImplicitGrant,
				constants.RefreshTokenGrant,
			},
			ResponseTypes: []constants.ResponseType{
				constants.CodeResponse,
				constants.IdTokenResponse,
				constants.TokenResponse,
				constants.CodeAndIdTokenResponse,
				constants.CodeAndTokenResponse,
				constants.IdTokenAndTokenResponse,
				constants.CodeAndIdTokenAndTokenResponse,
			},
		},
	}
}
