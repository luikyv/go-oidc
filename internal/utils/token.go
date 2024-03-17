package utils

import (
	"errors"
	"strings"

	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func HandleTokenCreation(
	ctx Context,
	request models.TokenRequest,
) (models.Token, error) {

	grantInfo, err := getGrantInfo(ctx, request)
	if err != nil {
		return models.Token{}, err
	}

	var token models.Token
	switch grantInfo.GrantType {
	case constants.ClientCredentials:
		token, err = handleClientCredentialsGrantTokenCreation(grantInfo)
	case constants.AuthorizationCode:
		token, err = handleAuthorizationCodeGrantTokenCreation(ctx, grantInfo)
	default:
		err = errors.New("invalid grant")
	}

	if err != nil {
		return models.Token{}, err
	}

	ctx.CrudManager.TokenSessionManager.Create(token)
	return token, nil
}

func getGrantInfo(
	ctx Context,
	request models.TokenRequest,
) (
	models.GrantInfo,
	error,
) {
	authenticatedClient, err := getAuthenticatedClient(
		ctx.CrudManager.ClientManager,
		models.ClientAuthnContext{
			ClientId:     request.ClientId,
			ClientSecret: request.ClientSecret,
		},
	)
	if err != nil {
		return models.GrantInfo{}, err
	}

	tokenModel, err := ctx.CrudManager.TokenModelManager.Get(authenticatedClient.DefaultTokenModelId)
	if err != nil {
		return models.GrantInfo{}, err
	}

	return models.GrantInfo{
		GrantType:           request.GrantType,
		AuthenticatedClient: authenticatedClient,
		TokenModel:          tokenModel,
		Scopes:              strings.Split(request.Scope, " "),
		AuthorizationCode:   request.AuthorizationCode,
		RedirectUri:         request.RedirectUri,
	}, nil
}

func getAuthenticatedClient(clientManager crud.ClientManager, authnContext models.ClientAuthnContext) (models.Client, error) {
	client, err := clientManager.Get(authnContext.ClientId)
	if err != nil {
		return models.Client{}, err
	}

	clientAuthnContext := models.ClientAuthnContext{
		ClientSecret: authnContext.ClientSecret,
	}
	if !client.Authenticator.IsAuthenticated(clientAuthnContext) {
		return models.Client{}, errors.New("client not authenticated")
	}

	return client, nil
}

//---------------------------------------- Client Credentials ----------------------------------------//

func handleClientCredentialsGrantTokenCreation(grantInfo models.GrantInfo) (models.Token, error) {
	if err := validateClientCredentialsGrantRequest(grantInfo); err != nil {
		return models.Token{}, err
	}

	return grantInfo.TokenModel.GenerateToken(models.TokenContextInfo{
		Subject:  grantInfo.AuthenticatedClient.Id,
		ClientId: grantInfo.AuthenticatedClient.Id,
		Scopes:   grantInfo.Scopes,
	}), nil
}

func validateClientCredentialsGrantRequest(grantInfo models.GrantInfo) error {
	if grantInfo.RedirectUri != "" || grantInfo.AuthorizationCode != "" {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid parameter for client credentials",
		}
	}
	if !grantInfo.AuthenticatedClient.AreScopesAllowed(grantInfo.Scopes) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidScope,
			ErrorDescription: "invalid scope",
		}
	}

	return nil
}

//---------------------------------------- Authorization Code ----------------------------------------//

func handleAuthorizationCodeGrantTokenCreation(ctx Context, grantInfo models.GrantInfo) (models.Token, error) {
	err := validateAuthorizationCodeGrantRequest(grantInfo)
	if err != nil {
		return models.Token{}, err
	}

	session, err := ctx.CrudManager.AuthnSessionManager.GetByAuthorizationCode(grantInfo.AuthorizationCode)
	if err != nil {
		return models.Token{}, err
	}

	if session.ClientId != grantInfo.AuthenticatedClient.Id {
		return models.Token{}, issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the authorization code was not issue to the client",
		}
	}

	return grantInfo.TokenModel.GenerateToken(models.TokenContextInfo{
		Subject:  session.Subject,
		ClientId: session.ClientId,
		Scopes:   session.Scopes,
	}), nil
}

func validateAuthorizationCodeGrantRequest(grantInfo models.GrantInfo) error {
	if len(grantInfo.Scopes) != 0 || grantInfo.AuthorizationCode == "" || grantInfo.RedirectUri == "" {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid parameter for authorization code",
		}
	}

	return nil
}
