package token_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/token"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestHandleGrantCreationShouldNotFindClient(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUpTest()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(models.TestClientId)

	// Then
	_, err := token.HandleGrantCreation(ctx, models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     "invalid_client_id",
			ClientSecretPost: models.TestClientSecret,
		},
		GrantType: constants.ClientCredentialsGrant,
		Scopes:    strings.Join(client.Scopes, " "),
	})

	// Assert
	if err == nil {
		t.Error("the should not be found")
		return
	}
}

func TestHandleGrantCreationShouldRejectUnauthenticatedClient(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUpTest()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(models.TestClientId)

	// Then
	_, err := token.HandleGrantCreation(ctx, models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     models.TestClientId,
			ClientSecretPost: "invalid_password",
		},
		GrantType: constants.ClientCredentialsGrant,
		Scopes:    client.Scopes[0],
	})

	// Assert
	var oauthErr issues.OAuthBaseError
	if err == nil || !errors.As(err, &oauthErr) {
		t.Error("the client should not be authenticated")
		return
	}
	if oauthErr.ErrorCode != constants.InvalidClient {
		t.Errorf("invalid error code: %s", oauthErr.ErrorCode)
		return
	}
}

func TestHandleGrantCreationWithDpop(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUpTest()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(models.TestClientId)
	req := models.TokenRequest{
		DpopJwt: "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYVRtMk95eXFmaHFfZk5GOVVuZXlrZG0yX0dCZnpZVldDNEI1Wlo1SzNGUSIsInkiOiI4eFRhUERFTVRtNXM1d1MzYmFvVVNNcU01R0VJWDFINzMwX1hqV2lRaGxRIn19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE1NjIyNjUyOTZ9.AzzSCVYIimNZyJQefZq7cF252PukDvRrxMqrrcH6FFlHLvpXyk9j8ybtS36GHlnyH_uuy2djQphfyHGeDfxidQ",
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     models.TestClientId,
			ClientSecretPost: models.TestClientSecret,
		},
		GrantType: constants.ClientCredentialsGrant,
		Scopes:    client.Scopes[0],
	}

	// Then
	_, err := token.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	grantSessionManager, _ := ctx.GrantSessionManager.(*inmemory.InMemoryGrantSessionManager)
	grantSessions := make([]models.GrantSession, 0, len(grantSessionManager.GrantSessions))
	for _, gs := range grantSessionManager.GrantSessions {
		grantSessions = append(grantSessions, gs)
	}
	if len(grantSessions) != 1 {
		t.Error("there should be only one token session")
		return
	}

	if grantSessions[0].JwkThumbprint != "BABEGlQNVH1K8KXO7qLKtvUFhAadQ5-dVGBfDfelwhQ" {
		t.Errorf("invalid jwk thumbprint. actual: %s", grantSessions[0].JwkThumbprint)
		return
	}
}
