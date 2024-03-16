package main

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/pkg/oauth"
)

func main() {

	oauthManager := oauth.NewManager()

	// Add Mocks
	oauthManager.AddTokenModel(models.OpaqueTokenModel{
		TokenLength: 20,
		BaseTokenModel: models.BaseTokenModel{
			Id:            "my_token_model",
			Issuer:        "example.com",
			ExpiresInSecs: 60,
			IsRefreshable: false,
		},
	})
	oauthManager.AddClient(models.Client{
		Id:                  "client_id",
		GrantTypes:          []constants.GrantType{constants.ClientCredentials},
		Scopes:              []string{"email"},
		DefaultTokenModelId: "my_token_model",
		Authenticator:       models.NoneClientAuthenticator{},
	})

	oauthManager.Run(80)
}
