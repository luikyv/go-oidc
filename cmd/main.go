package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/pkg/oauth"
)

func main() {

	oauthManager := oauth.NewManager(oauth.SetMockedEntitiesConfig, oauth.SetMockedSessionsConfig)

	// Add Mocks
	oauthManager.AddTokenModel(models.OpaqueTokenModel{
		TokenLength: 20,
		BaseTokenModel: models.BaseTokenModel{
			Id:            "my_token_model",
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
			IsRefreshable: false,
		},
	})
	oauthManager.AddClient(models.Client{
		Id:                  "client_id",
		GrantTypes:          []constants.GrantType{constants.ClientCredentials, constants.AuthorizationCode},
		Scopes:              []string{"email"},
		RedirectUris:        []string{"http://localhost:80/callback"},
		ResponseTypes:       []constants.ResponseType{constants.Code},
		DefaultTokenModelId: "my_token_model",
		Authenticator:       models.NoneClientAuthenticator{},
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

			if passwordForm.Password != "password" {
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
	// http://localhost:80/authorize?client_id=client_id&scope=email&response_type=code&state=random_state&redirect_uri=http%3A%2F%2Flocalhost%3A80%2Fcallback
	oauthManager.AddPolicy(policy)
	oauthManager.Run(80)
}
