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
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
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

func getClientJwk() jose.JSONWebKey {
	absPath, _ := filepath.Abs("./client_jwk.json")
	clientJwkFile, err := os.Open(absPath)
	if err != nil {
		panic(err.Error())
	}
	defer clientJwkFile.Close()
	clientJwkBytes, err := io.ReadAll(clientJwkFile)
	if err != nil {
		panic(err.Error())
	}
	var clientJwk jose.JSONWebKey
	clientJwk.UnmarshalJSON(clientJwkBytes)

	return clientJwk
}

func createClientAssertion(client models.Client, jwk jose.JSONWebKey) string {
	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", "random value"),
	)
	claims := map[string]any{
		string(constants.Issuer):   client.Id,
		string(constants.Subject):  client.Id,
		string(constants.IssuedAt): createdAtTimestamp,
		string(constants.Expiry):   createdAtTimestamp,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return assertion
}

func main() {
	clientId := "client_id"
	opaqueTokenModelId := "opaque_token_model"
	jwtTokenModelId := "jwt_token_model"
	userPassword := "password"
	privateKeyId := "rsa_key"
	jwks := loadJwks()

	// Create the manager.
	oauthManager := oauth.NewManager(jwks, oauth.SetMockedEntitiesConfig, oauth.SetMockedSessionsConfig)

	// Add token model mocks.
	oauthManager.AddTokenModel(models.OpaqueTokenModel{
		TokenLength: 20,
		TokenModelInfo: models.TokenModelInfo{
			Id:            opaqueTokenModelId,
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
			IsRefreshable: false,
			OpenIdKeyId:   privateKeyId,
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
			OpenIdKeyId:         privateKeyId,
		},
	})

	// Add client mock.
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("secret"), 0)
	// Create the client
	client := models.Client{
		Id:                  clientId,
		GrantTypes:          []constants.GrantType{constants.ClientCredentials, constants.AuthorizationCode, constants.RefreshToken},
		Scopes:              []string{"openid", "email", "profile"},
		RedirectUris:        []string{"http://localhost:80/callback"},
		ResponseTypes:       []constants.ResponseType{constants.Code},
		DefaultTokenModelId: jwtTokenModelId,
		Authenticator: models.SecretClientAuthenticator{
			HashedSecret: string(hashedSecret),
		},
		Attributes: map[string]string{
			"custom_attribute": "random_attribute",
		},
	}
	oauthManager.AddClient(client)

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
			session.SetCustomTokenClaim("custom_claim", "random_value")
			session.SetCustomTokenClaim("client_attribute", session.ClientAttributes["custom_attribute"])
			session.SetCustomIdTokenClaim("email", "random@email.com")
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
