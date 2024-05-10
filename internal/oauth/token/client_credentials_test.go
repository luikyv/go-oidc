package token_test

import (
	"strings"
	"testing"

	"github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/token"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestClientCredentialsHandleGrantCreation(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUpTest()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(models.TestClientId)
	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     models.TestClientId,
			ClientSecretPost: models.TestClientSecret,
		},
		GrantType: constants.ClientCredentialsGrant,
		Scope:     strings.Join(client.Scopes, " "),
	}

	// Then
	token, err := token.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if token.ClientId != models.TestClientId {
		t.Error("the token was assigned to a different client")
		return
	}

	if token.Subject != models.TestClientId {
		t.Error("the token subject should be the client")
		return
	}

	grantSessionManager, _ := ctx.GrantSessionManager.(*inmemory.InMemoryGrantSessionManager)
	tokens := make([]models.GrantSession, 0, len(grantSessionManager.GrantSessions))
	for _, tk := range grantSessionManager.GrantSessions {
		tokens = append(tokens, tk)
	}
	if len(tokens) != 1 {
		t.Error("there should be only one token session")
		return
	}
}
