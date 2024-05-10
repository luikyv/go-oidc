package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/utils"
	"github.com/luikymagno/auth-server/pkg/oauth"
)

// func loadJwks() jose.JSONWebKeySet {
// 	absPath, _ := filepath.Abs("./jwks.json")
// 	jwksFile, err := os.Open(absPath)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	defer jwksFile.Close()
// 	jwksBytes, err := io.ReadAll(jwksFile)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	var jwks jose.JSONWebKeySet
// 	json.Unmarshal(jwksBytes, &jwks)

// 	return jwks
// }

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
	port := 83
	// issuer := fmt.Sprintf("https://host.docker.internal:%v", port)
	issuer := fmt.Sprintf("https://localhost:%v", port)
	privatePs256Jwk := unit.GetTestPrivatePs256Jwk()

	// Create the manager.
	oauthManager := oauth.NewManager(
		issuer,
		jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privatePs256Jwk, privatePs256Jwk}},
		privatePs256Jwk.KeyID,
		"./templates/*",
		oauth.ConfigureInMemoryClientAndScope,
		oauth.ConfigureInMemoryGrantModel,
		oauth.ConfigureInMemorySessions,
	)

	// Add mocks.
	opaqueGrantModel := models.GetTestOpaqueGrantModel(privatePs256Jwk)
	oauthManager.AddGrantModel(opaqueGrantModel)

	jwtGrantModel := models.GetTestJwtGrantModel(privatePs256Jwk)
	oauthManager.AddGrantModel(jwtGrantModel)

	client := models.GetSecretPostTestClient()
	client.RedirectUris = append(client.RedirectUris, issuer+"/callback")
	client.DefaultGrantModelId = jwtGrantModel.Meta.Id
	oauthManager.AddClient(client)

	// Create Policy
	policy := utils.NewPolicy(
		"policy",
		func(c models.AuthnSession, ctx *gin.Context) bool { return true },
		NoInteractionStep,
	)

	// Run
	oauthManager.AddPolicy(policy)
	oauthManager.RunTLS(port)
}
