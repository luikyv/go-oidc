package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/pkg/oauth"
	"golang.org/x/crypto/bcrypt"
)

func main() {

	jwks := ""
	oauthManager := oauth.NewManager(jwks, oauth.SetMockedEntitiesConfig, oauth.SetMockedSessionsConfig)

	clientId := "client_id"
	clientSecret := "secret"
	tokenModelId := "my_token_model"
	userPassword := "password"
	// Add Mocks
	// oauthManager.AddTokenModel(models.OpaqueTokenModel{
	// 	TokenLength: 20,
	// 	BaseTokenModel: models.BaseTokenModel{
	// 		Id:            tokenModelId,
	// 		Issuer:        "https://example.com",
	// 		ExpiresInSecs: 60,
	// 		IsRefreshable: false,
	// 	},
	// })
	oauthManager.AddTokenModel(models.JWTTokenModel{
		KeyId: "",
		BaseTokenModel: models.BaseTokenModel{
			Id:            tokenModelId,
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
			IsRefreshable: false,
		},
	})
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	oauthManager.AddClient(models.Client{
		Id:                  clientId,
		GrantTypes:          []constants.GrantType{constants.ClientCredentials, constants.AuthorizationCode},
		Scopes:              []string{"email"},
		RedirectUris:        []string{"http://localhost:80/callback"},
		ResponseTypes:       []constants.ResponseType{constants.Code},
		DefaultTokenModelId: tokenModelId,
		Authenticator: models.SecretClientAuthenticator{
			HashedSecret: string(hashedSecret),
		},
	})

	// Create Steps
	passwordStep := models.NewStep(
		"password",
		models.FinishFlowSuccessfullyStep,
		models.FinishFlowWithFailureStep,
		func(session *models.AuthnSession, ctx *gin.Context) constants.AuthnStatus {

			var passwordForm struct {
				Password string `form:"password"`
			}
			ctx.ShouldBind(&passwordForm)

			if passwordForm.Password == "" {
				ctx.HTML(http.StatusOK, "password.html", gin.H{
					"callbackId": session.CallbackId,
				})
				return constants.InProgress
			}

			if passwordForm.Password != userPassword {
				ctx.HTML(http.StatusOK, "password.html", gin.H{
					"callbackId": session.CallbackId,
					"error":      "invalid password",
				})
				return constants.InProgress
			}

			return constants.Success
		},
	)

	identityStep := models.NewStep(
		"identity",
		passwordStep,
		models.FinishFlowWithFailureStep,
		func(session *models.AuthnSession, ctx *gin.Context) constants.AuthnStatus {

			var identityForm struct {
				Username string `form:"username"`
			}
			ctx.ShouldBind(&identityForm)

			a := ctx.PostForm("username")
			fmt.Println(a)

			if identityForm.Username == "" {
				ctx.HTML(http.StatusOK, "identity.html", gin.H{
					"callbackId": session.CallbackId,
				})
				return constants.InProgress
			}

			session.SetUserId(identityForm.Username)
			return constants.Success
		},
	)

	// Create Policy
	policy := models.NewPolicy(
		"policy",
		identityStep,
		func(c models.Client, ctx *gin.Context) bool { return true },
	)

	// Run
	oauthManager.AddPolicy(policy)
	oauthManager.Run(80)
}
