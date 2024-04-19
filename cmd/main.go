package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
	"github.com/luikymagno/auth-server/pkg/oauth"
	"golang.org/x/crypto/bcrypt"
)

func loadJwks() jose.JSONWebKeySet {
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

	return jwks
}

// func getClientJwk() jose.JSONWebKey {
// 	absPath, _ := filepath.Abs("./client_jwk.json")
// 	clientJwkFile, err := os.Open(absPath)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	defer clientJwkFile.Close()
// 	clientJwkBytes, err := io.ReadAll(clientJwkFile)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	var clientJwk jose.JSONWebKey
// 	clientJwk.UnmarshalJSON(clientJwkBytes)

// 	return clientJwk
// }

// func createClientAssertion(client models.Client, jwk jose.JSONWebKey) string {
// 	createdAtTimestamp := unit.GetTimestampNow()
// 	signer, _ := jose.NewSigner(
// 		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
// 		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", "random value"),
// 	)
// 	claims := map[string]any{
// 		string(constants.Issuer):   client.Id,
// 		string(constants.Subject):  client.Id,
// 		string(constants.IssuedAt): createdAtTimestamp,
// 		string(constants.Expiry):   createdAtTimestamp,
// 	}
// 	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()

// 	return assertion
// }

func main() {
	clientId := "random_client"
	clientSecret := "random_secret"
	clientSecretSalt := "random_salt"
	opaqueGrantModelId := "opaque_token_model"
	jwtGrantModelId := "jwt_token_model"
	userPassword := "password"
	privateKeyId := "rsa_key"
	issuer := "https://example.com"
	jwks := loadJwks()

	// Create the manager.
	oauthManager := oauth.NewManager(jwks, "./templates/*", oauth.SetMockedEntitiesConfig, oauth.SetMockedSessionsConfig)

	// Add token model mocks.
	oauthManager.AddGrantModel(models.GrantModel{
		TokenMaker: models.OpaqueTokenMaker{
			TokenLength: 20,
		},
		Meta: models.GrantMetaInfo{
			Id:            opaqueGrantModelId,
			Issuer:        issuer,
			ExpiresInSecs: 60,
			IsRefreshable: false,
			OpenIdKeyId:   privateKeyId,
		},
	})
	oauthManager.AddGrantModel(models.GrantModel{
		TokenMaker: models.JWTTokenMaker{
			KeyId: privateKeyId,
		},
		Meta: models.GrantMetaInfo{
			Id:                  jwtGrantModelId,
			Issuer:              issuer,
			ExpiresInSecs:       60,
			IsRefreshable:       true,
			RefreshLifetimeSecs: 60,
			OpenIdKeyId:         privateKeyId,
		},
	})

	// Add client mock.
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecretSalt+clientSecret), 0)
	// Create the client
	client := models.Client{
		Id:                  clientId,
		GrantTypes:          constants.GrantTypes,
		Scopes:              []string{"openid", "email", "profile"},
		RedirectUris:        []string{"http://localhost:80/callback", "https://localhost.emobix.co.uk:8443/test/a/first_test/callback", "https://localhost:8443/test/a/first_test/callback"},
		ResponseTypes:       constants.ResponseTypes,
		ResponseModes:       constants.ResponseModes,
		DefaultGrantModelId: jwtGrantModelId,
		Authenticator: models.SecretPostClientAuthenticator{
			Salt:         clientSecretSalt,
			HashedSecret: string(hashedSecret),
		},
		Attributes: map[string]string{
			"custom_attribute": "random_attribute",
		},
	}
	oauthManager.AddClient(client)

	// Create Steps
	passwordStep := utils.NewStep(
		"password",
		utils.FinishFlowSuccessfullyStep,
		utils.FinishFlowWithFailureStep,
		func(ctx utils.Context, session *models.AuthnSession) constants.AuthnStatus {

			var passwordForm struct {
				Password string `form:"password"`
			}
			ctx.RequestContext.ShouldBind(&passwordForm)

			if passwordForm.Password == "" {
				ctx.RequestContext.HTML(http.StatusOK, "password.html", gin.H{
					"callbackId": session.CallbackId,
				})
				return constants.InProgress
			}

			if passwordForm.Password != userPassword {
				ctx.RequestContext.HTML(http.StatusOK, "password.html", gin.H{
					"callbackId": session.CallbackId,
					"error":      "invalid password",
				})
				return constants.InProgress
			}

			return constants.Success
		},
	)

	identityStep := utils.NewStep(
		"identity",
		passwordStep,
		utils.FinishFlowWithFailureStep,
		func(ctx utils.Context, session *models.AuthnSession) constants.AuthnStatus {

			var identityForm struct {
				Username string `form:"username"`
			}
			ctx.RequestContext.ShouldBind(&identityForm)

			a := ctx.RequestContext.PostForm("username")
			fmt.Println(a)

			if identityForm.Username == "" {
				ctx.RequestContext.HTML(http.StatusOK, "identity.html", gin.H{
					"callbackId": session.CallbackId,
				})
				return constants.InProgress
			}

			session.SetUserId(identityForm.Username)
			session.SetCustomTokenClaim("custom_claim", "random_value")
			session.SetCustomTokenClaim("client_attribute", session.ClientAttributes["custom_attribute"])
			if slices.Contains(session.Scopes, "email") {
				session.SetCustomIdTokenClaim("email", "random@email.com")
			}
			return constants.Success
		},
	)

	// Create Policy
	policy := utils.NewPolicy(
		"policy",
		identityStep,
		func(c models.Client, ctx *gin.Context) bool { return true },
	)

	// Run
	oauthManager.AddPolicy(policy)
	oauthManager.RunTLS(443)
}
