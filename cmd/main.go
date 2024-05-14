package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/utils"
	"github.com/luikymagno/auth-server/pkg/oauth"
)

func main() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(jsonHandler)
	port := 83
	issuer := fmt.Sprintf("https://host.docker.internal:%v", port)
	// issuer := fmt.Sprintf("https://localhost:%v", port)
	privatePs256Jwk := unit.GetTestPrivatePs256Jwk("server_key")

	// Create the manager.
	oauthManager := oauth.NewManager(
		issuer,
		jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privatePs256Jwk, privatePs256Jwk}},
		"./templates/*",
		oauth.ConfigureInMemoryClientAndScope,
		oauth.ConfigureInMemoryGrantModel,
		oauth.ConfigureInMemorySessions,
	)
	oauthManager.EnablePushedAuthorizationRequests(false)
	oauthManager.EnableJwtSecuredAuthorizationRequests(privatePs256Jwk.KeyID, false)

	// Add mocks.
	opaqueGrantModel := models.GetTestOpaqueGrantModel(privatePs256Jwk)
	oauthManager.AddGrantModel(opaqueGrantModel)

	jwtGrantModel := models.GetTestJwtGrantModel(privatePs256Jwk)
	oauthManager.AddGrantModel(jwtGrantModel)

	privateClientJwk := unit.GetTestPrivatePs256Jwk("client_key")
	logger.Debug("private client JWK", slog.Any("JWKS", jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateClientJwk}}))
	client := models.GetPrivateKeyJwtTestClient(privateClientJwk.Public())
	// client := models.GetSecretPostTestClient()
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
