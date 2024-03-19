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

func TestHandleTokenCreationWhenClientIsNotFound(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()

	// Then
	_, err := utils.HandleTokenCreation(ctx, models.TokenRequest{
		ClientId:     "invalid_client_id",
		GrantType:    constants.ClientCredentials,
		Scope:        strings.Join(utils.ValidClient.Scopes, " "),
		ClientSecret: utils.ValidClientSecret,
	})

	// Assert
	var jsonError issues.EntityNotFoundError
	if err == nil || !errors.As(err, &jsonError) {
		t.Error("the should not be found")
		return
	}
}

func TestHandleTokenCreationWhenClientIsNotAuthenticated(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()

	// Then
	_, err := utils.HandleTokenCreation(ctx, models.TokenRequest{
		ClientId:     utils.ValidClient.Id,
		GrantType:    constants.ClientCredentials,
		Scope:        strings.Join(utils.ValidClient.Scopes, " "),
		ClientSecret: "invalid_password",
	})

	// Assert
	var jsonError issues.JsonError
	if err == nil || !errors.As(err, &jsonError) {
		t.Error("the client should be authenticated")
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
	req := models.TokenRequest{
		ClientId:     utils.ValidClient.Id,
		GrantType:    constants.ClientCredentials,
		Scope:        strings.Join(utils.ValidClient.Scopes, " "),
		ClientSecret: utils.ValidClientSecret,
	}

	// Then
	token, err := utils.HandleTokenCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if token.ClientId != utils.ValidClient.Id {
		t.Error("the token was assigned to a different client")
		return
	}

	if token.Subject != utils.ValidClient.Id {
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

	authorizationCode := "random_authz_code"
	session := models.AuthnSession{
		ClientId:          utils.ValidClient.Id,
		Scopes:            utils.ValidClient.Scopes,
		RedirectUri:       utils.ValidClient.RedirectUris[0],
		AuthorizationCode: authorizationCode,
		Subject:           "user_id",
	}
	ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(session)

	req := models.TokenRequest{
		ClientId:          utils.ValidClient.Id,
		GrantType:         constants.AuthorizationCode,
		ClientSecret:      utils.ValidClientSecret,
		RedirectUri:       utils.ValidClient.RedirectUris[0],
		AuthorizationCode: authorizationCode,
	}

	// Then
	token, err := utils.HandleTokenCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	if token.ClientId != utils.ValidClient.Id {
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
