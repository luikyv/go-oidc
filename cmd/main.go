package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/pkg/oauth"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	clientId := "client_id"
	clientSecret := "secret"
	opaqueTokenModelId := "opaque_token_model"
	jwtTokenModelId := "jwt_token_model"
	userPassword := "password"
	privateKeyId := "rsa_key"

	// Load the private JWKS.
	absPath, _ := filepath.Abs("./jwks.json")
	jwksFile, err := os.Open(absPath)
	if err != nil {
		panic(err.Error())
	}
	defer jwksFile.Close()
	jwksBytes, err := io.ReadAll(jwksFile)
	if err != nil {
		panic(err.Error())
	}
	var jwks jose.JSONWebKeySet
	json.Unmarshal(jwksBytes, &jwks)

	// Create the manager.
	oauthManager := oauth.NewManager(jwks, oauth.SetMockedEntitiesConfig, oauth.SetMockedSessionsConfig)

	// Add Mocks
	oauthManager.AddTokenModel(models.OpaqueTokenModel{
		TokenLength: 20,
		TokenModelInfo: models.TokenModelInfo{
			Id:            opaqueTokenModelId,
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
			IsRefreshable: false,
		},
	})
	oauthManager.AddTokenModel(models.JWTTokenModel{
		KeyId: privateKeyId,
		TokenModelInfo: models.TokenModelInfo{
			Id:                  jwtTokenModelId,
			Issuer:              "https://example.com",
			ExpiresInSecs:       60,
			IsRefreshable:       true,
			RefreshLifetimeSecs: 60,
		},
	})
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	oauthManager.AddClient(models.Client{
		Id:                  clientId,
		GrantTypes:          []constants.GrantType{constants.ClientCredentials, constants.AuthorizationCode, constants.RefreshToken},
		Scopes:              []string{"email"},
		RedirectUris:        []string{"http://localhost:80/callback"},
		ResponseTypes:       []constants.ResponseType{constants.Code},
		DefaultTokenModelId: jwtTokenModelId,
		Authenticator: models.SecretClientAuthenticator{
			HashedSecret: string(hashedSecret),
		},
		Attributes: map[string]string{
			"custom_attribute": "random_attribute",
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
			session.SetCustomClaim("custom_claim", "random_value")
			session.SetCustomClaim("client_attribute", session.ClientAttributes["custom_attribute"])
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
