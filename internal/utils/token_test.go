package utils_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/luikymagno/auth-server/internal/crud/mock"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestHandleGrantCreationShouldNotFindClient(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)

	// Then
	_, err := utils.HandleGrantCreation(ctx, models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     "invalid_client_id",
			ClientSecretPost: utils.ValidClientSecret,
		},
		GrantType: constants.ClientCredentialsGrant,
		Scope:     strings.Join(client.Scopes, " "),
	})

	// Assert
	if err == nil || !errors.Is(err, issues.ErrorEntityNotFound) {
		t.Error("the should not be found")
		return
	}
}

func TestHandleGrantCreationShouldRejectUnauthenticatedClient(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)

	// Then
	_, err := utils.HandleGrantCreation(ctx, models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     utils.ValidClientId,
			ClientSecretPost: "invalid_password",
		},
		GrantType: constants.ClientCredentialsGrant,
		Scope:     strings.Join(client.Scopes, " "),
	})

	// Assert
	var jsonError issues.OAuthError
	if err == nil || !errors.As(err, &jsonError) {
		t.Error("the client should not be authenticated")
		return
	}
	if jsonError.ErrorCode != constants.InvalidClient {
		t.Errorf("invalid error code: %s", jsonError.ErrorCode)
		return
	}
}

func TestClientCredentialsHandleGrantCreation(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)
	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     utils.ValidClientId,
			ClientSecretPost: utils.ValidClientSecret,
		},
		GrantType: constants.ClientCredentialsGrant,
		Scope:     strings.Join(client.Scopes, " "),
	}

	// Then
	token, err := utils.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if token.ClientId != utils.ValidClientId {
		t.Error("the token was assigned to a different client")
		return
	}

	if token.Subject != utils.ValidClientId {
		t.Error("the token subject should be the client")
		return
	}

	grantSessionManager, _ := ctx.GrantSessionManager.(*mock.MockedGrantSessionManager)
	tokens := make([]models.GrantSession, 0, len(grantSessionManager.GrantSessions))
	for _, tk := range grantSessionManager.GrantSessions {
		tokens = append(tokens, tk)
	}
	if len(tokens) != 1 {
		t.Error("there should be only one token session")
		return
	}
}

func TestAuthorizationCodeHandleGrantCreation(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)

	authorizationCode := "random_authz_code"
	session := models.AuthnSession{
		ClientId:              utils.ValidClientId,
		Scopes:                client.Scopes,
		RedirectUri:           client.RedirectUris[0],
		AuthorizationCode:     authorizationCode,
		Subject:               "user_id",
		CreatedAtTimestamp:    unit.GetTimestampNow(),
		AuthorizedAtTimestamp: unit.GetTimestampNow(),
		Store:                 make(map[string]string),
		AdditionalTokenClaims: make(map[string]string),
	}
	ctx.AuthnSessionManager.CreateOrUpdate(session)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     utils.ValidClientId,
			ClientSecretPost: utils.ValidClientSecret,
		},
		GrantType:         constants.AuthorizationCodeGrant,
		RedirectUri:       client.RedirectUris[0],
		AuthorizationCode: authorizationCode,
	}

	// Then
	token, err := utils.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if token.ClientId != utils.ValidClientId {
		t.Error("the token was assigned to a different client")
		return
	}

	if token.Subject != session.Subject {
		t.Error("the token subject should be the client")
		return
	}

	tokens := utils.GetTokenFromMock(ctx)
	if len(tokens) != 1 {
		t.Error("there should be only one token session")
		return
	}
}

func TestRefreshTokenHandleGrantCreation(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)

	refreshToken := "random_refresh_token"
	username := "user_id"
	token := models.GrantSession{
		Id:                    "random_id",
		GrantModelId:          utils.ValidGrantModelId,
		Token:                 "token",
		ExpiresInSecs:         60,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresIn: 30,
		CreatedAtTimestamp:    unit.GetTimestampNow(),
		Subject:               username,
		ClientId:              utils.ValidClientId,
		Scopes:                client.Scopes,
	}
	ctx.GrantSessionManager.CreateOrUpdate(token)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     utils.ValidClientId,
			ClientSecretPost: utils.ValidClientSecret,
		},
		GrantType:    constants.RefreshTokenGrant,
		RefreshToken: refreshToken,
	}

	// Then
	newToken, err := utils.HandleGrantCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if newToken.ClientId != utils.ValidClientId {
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

	tokens := utils.GetTokenFromMock(ctx)
	if len(tokens) != 1 {
		t.Error("there should be only one token session")
		return
	}
}

func TestRefreshTokenHandleGrantCreationShouldDenyExpiredRefreshToken(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)

	refreshToken := "random_refresh_token"
	username := "user_id"
	token := models.GrantSession{
		Id:                    "random_id",
		GrantModelId:          utils.ValidGrantModelId,
		Token:                 "token",
		RefreshToken:          refreshToken,
		ExpiresInSecs:         60,
		RefreshTokenExpiresIn: 0,
		CreatedAtTimestamp:    unit.GetTimestampNow() - 10,
		Subject:               username,
		ClientId:              utils.ValidClientId,
		Scopes:                client.Scopes,
	}
	ctx.GrantSessionManager.CreateOrUpdate(token)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientIdPost:     utils.ValidClientId,
			ClientSecretPost: utils.ValidClientSecret,
		},
		GrantType:    constants.RefreshTokenGrant,
		RefreshToken: refreshToken,
	}

	// Then
	_, err := utils.HandleGrantCreation(ctx, req)

	// Assert
	if err == nil {
		t.Errorf("the refresh token request should be denied")
		return
	}

}
