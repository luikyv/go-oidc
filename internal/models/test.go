package models

import (
	"github.com/luikymagno/auth-server/internal/constants"
)

const (
	TestClientId           string = "random_client_id"
	TestClientSecret       string = "random_client_secret"
	TestOpaqueGrantModelId string = "opaque_grant_model_id"
	TestJwtGrantModelId    string = "jwt_grant_model_id"
)

func GetTestClient() Client {
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
