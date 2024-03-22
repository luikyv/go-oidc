package utils_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/luikymagno/auth-server/internal/crud/mock"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
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
		ClientId:     "invalid_client_id",
		GrantType:    constants.ClientCredentials,
		Scope:        strings.Join(client.Scopes, " "),
		ClientSecret: utils.ValidClientSecret,
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
		ClientId:     utils.ValidClientId,
		GrantType:    constants.ClientCredentials,
		Scope:        strings.Join(client.Scopes, " "),
		ClientSecret: "invalid_password",
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
		ClientId:     utils.ValidClientId,
		GrantType:    constants.ClientCredentials,
		Scope:        strings.Join(client.Scopes, " "),
		ClientSecret: utils.ValidClientSecret,
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
		ClientId:          utils.ValidClientId,
		GrantType:         constants.AuthorizationCode,
		ClientSecret:      utils.ValidClientSecret,
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
