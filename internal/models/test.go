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

func GetTestOpaqueGrantModel(privateJwk jose.JSONWebKey) GrantModel {
	return GrantModel{
		TokenMaker: OpaqueTokenMaker{
			TokenLength: 20,
		},
		Meta: GrantMetaInfo{
			Id:               TestOpaqueGrantModelId,
			OpenIdPrivateJwk: privateJwk,
			ExpiresInSecs:    60,
			IsRefreshable:    true,
		},
	}
}

func GetTestJwtGrantModel(privateJwk jose.JSONWebKey) GrantModel {
	return GrantModel{
		TokenMaker: JWTTokenMaker{
			PrivateJwk: privateJwk,
		},
		Meta: GrantMetaInfo{
			Id:               TestJwtGrantModelId,
			OpenIdPrivateJwk: privateJwk,
			ExpiresInSecs:    60,
			IsRefreshable:    true,
		},
	}
}

func GetTestSecretPostAuthenticator() SecretPostClientAuthenticator {
	clientSecretSalt := "random_salt"
	clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecretSalt+TestClientSecret), 0)
	return SecretPostClientAuthenticator{
		Salt:         clientSecretSalt,
		HashedSecret: string(clientHashedSecret),
	}
}

func GetSecretPostTestClient() Client {
	return GetTestClient(GetTestSecretPostAuthenticator())
}

func GetNoneAuthTestClient() Client {
	return GetTestClient(NoneClientAuthenticator{})
}

func GetTestClient(authenticator ClientAuthenticator) Client {
	return Client{
		Id:                  TestClientId,
		RedirectUris:        []string{"https://example.com"},
		Scopes:              []string{"scope1", "scope2", constants.OpenIdScope},
		GrantTypes:          constants.GrantTypes,
		ResponseTypes:       constants.ResponseTypes,
		ResponseModes:       constants.ResponseModes,
		DefaultGrantModelId: TestOpaqueGrantModelId,
		Authenticator:       authenticator,
	}
}
