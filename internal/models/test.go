package models

import "github.com/luikymagno/goidc/pkg/goidc"

const (
	TestClientId           string = "random_client_id"
	TestClientSecret       string = "random_client_secret"
	TestOpaqueGrantModelId string = "opaque_grant_model_id"
	TestJwtGrantModelId    string = "jwt_grant_model_id"
)

func GetTestClient() goidc.Client {
	return goidc.Client{
		Id: TestClientId,
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:  goidc.NoneAuthn,
			RedirectUris: []string{"https://example.com"},
			Scopes:       "scope1 scope2 " + goidc.OpenIdScope,
			GrantTypes: []goidc.GrantType{
				goidc.AuthorizationCodeGrant,
				goidc.ClientCredentialsGrant,
				goidc.ImplicitGrant,
				goidc.RefreshTokenGrant,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.CodeResponse,
				goidc.IdTokenResponse,
				goidc.TokenResponse,
				goidc.CodeAndIdTokenResponse,
				goidc.CodeAndTokenResponse,
				goidc.IdTokenAndTokenResponse,
				goidc.CodeAndIdTokenAndTokenResponse,
			},
		},
	}
}
