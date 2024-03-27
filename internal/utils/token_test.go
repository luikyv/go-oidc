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

func TestHandleTokenCreationShouldNotFindClient(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)

	// Then
	_, err := utils.HandleTokenCreation(ctx, models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId:     "invalid_client_id",
			ClientSecret: utils.ValidClientSecret,
		},
		GrantType: constants.ClientCredentials,
		Scope:     strings.Join(client.Scopes, " "),
	})

	// Assert
	var jsonError issues.EntityNotFoundError
	if err == nil || !errors.As(err, &jsonError) {
		t.Error("the should not be found")
		return
	}
}

func TestHandleTokenCreationShouldRejectUnauthenticatedClient(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)

	// Then
	_, err := utils.HandleTokenCreation(ctx, models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId:     utils.ValidClientId,
			ClientSecret: "invalid_password",
		},
		GrantType: constants.ClientCredentials,
		Scope:     strings.Join(client.Scopes, " "),
	})

	// Assert
	var jsonError issues.JsonError
	if err == nil || !errors.As(err, &jsonError) {
		t.Error("the client should not be authenticated")
		return
	}
	if jsonError.ErrorCode != constants.AccessDenied {
		t.Errorf("invalid error code: %s", jsonError.ErrorCode)
		return
	}
}

func TestClientCredentialsHandleTokenCreation(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)
	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId:     utils.ValidClientId,
			ClientSecret: utils.ValidClientSecret,
		},
		GrantType: constants.ClientCredentials,
		Scope:     strings.Join(client.Scopes, " "),
	}

	// Then
	token, err := utils.HandleTokenCreation(ctx, req)

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

	tokenSessionManager, _ := ctx.CrudManager.TokenSessionManager.(*mock.MockedTokenSessionManager)
	tokens := make([]models.Token, 0, len(tokenSessionManager.Tokens))
	for _, tk := range tokenSessionManager.Tokens {
		tokens = append(tokens, tk)
	}
	if len(tokens) != 1 {
		t.Error("there should be only one token session")
		return
	}
}

func TestAuthorizationCodeHandleTokenCreation(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)

	authorizationCode := "random_authz_code"
	session := models.AuthnSession{
		ClientId:          utils.ValidClientId,
		Scopes:            client.Scopes,
		RedirectUri:       client.RedirectUris[0],
		AuthorizationCode: authorizationCode,
		Subject:           "user_id",
	}
	ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(session)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId:     utils.ValidClientId,
			ClientSecret: utils.ValidClientSecret,
		},
		GrantType:         constants.AuthorizationCode,
		RedirectUri:       client.RedirectUris[0],
		AuthorizationCode: authorizationCode,
	}

	// Then
	token, err := utils.HandleTokenCreation(ctx, req)

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

func TestRefreshTokenHandleTokenCreation(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)

	refreshToken := "random_refresh_token"
	username := "user_id"
	token := models.Token{
		Id:                 "random_id",
		TokenModelId:       utils.ValidTokenModelId,
		TokenString:        "token",
		RefreshToken:       refreshToken,
		ExpiresInSecs:      60,
		CreatedAtTimestamp: unit.GetTimestampNow(),
		TokenContextInfo: models.TokenContextInfo{
			Subject:  username,
			ClientId: utils.ValidClientId,
			Scopes:   client.Scopes,
		},
	}
	ctx.CrudManager.TokenSessionManager.Create(token)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId:     utils.ValidClientId,
			ClientSecret: utils.ValidClientSecret,
		},
		GrantType:    constants.RefreshToken,
		RefreshToken: refreshToken,
	}

	// Then
	newToken, err := utils.HandleTokenCreation(ctx, req)

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
