package token_test

import (
	"testing"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/token"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestRefreshTokenHandleGrantCreation(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUpTest()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(models.TestClientId)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := models.GrantSession{
		Token:        "token",
		RefreshToken: refreshToken,
		GrantOptions: models.GrantOptions{
			SessionId:          "random_id",
			CreatedAtTimestamp: unit.GetTimestampNow(),
			Subject:            username,
			ClientId:           models.TestClientId,
			Scopes:             client.Scopes,
			TokenOptions: models.TokenOptions{
				ExpiresInSecs:             60,
				RefreshTokenExpiresInSecs: 30,
			},
		},
	}
	ctx.GrantSessionManager.CreateOrUpdate(grantSession)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     models.TestClientId,
			ClientSecretPost: models.TestClientSecret,
		},
		GrantType:    constants.RefreshTokenGrant,
		RefreshToken: refreshToken,
	}

	// Then
	newToken, err := token.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if newToken.ClientId != models.TestClientId {
		t.Error("the token was assigned to a different client")
		return
	}

	if newToken.Subject != username {
		t.Error("the token subject should be the client")
		return
	}

	if newToken.RefreshToken == "" || newToken.RefreshToken == refreshToken {
		t.Error("the new refresh token is not valid")
		return
	}

	grantSessions := utils.GetGrantSessionsFromTestContext(ctx)
	if len(grantSessions) != 1 {
		t.Error("there should be only one grant session")
		return
	}
}

func TestRefreshTokenHandleGrantCreationShouldDenyExpiredRefreshToken(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUpTest()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(models.TestClientId)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := models.GrantSession{
		Token:        "token",
		RefreshToken: refreshToken,
		GrantOptions: models.GrantOptions{
			SessionId:          "random_id",
			CreatedAtTimestamp: unit.GetTimestampNow() - 10,
			Subject:            username,
			ClientId:           models.TestClientId,
			Scopes:             client.Scopes,
			TokenOptions: models.TokenOptions{
				ExpiresInSecs:             60,
				RefreshTokenExpiresInSecs: 0,
			},
		},
	}
	ctx.GrantSessionManager.CreateOrUpdate(grantSession)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     models.TestClientId,
			ClientSecretPost: models.TestClientSecret,
		},
		GrantType:    constants.RefreshTokenGrant,
		RefreshToken: refreshToken,
	}

	// Then
	_, err := token.HandleGrantCreation(ctx, req)

	// Assert
	if err == nil {
		t.Errorf("the refresh token request should be denied")
		return
	}

}
