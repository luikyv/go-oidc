package utils

import (
	"errors"
	"strings"

	"github.com/luikymagno/auth-server/internal/crud"
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
		token, err = handleAuthorizationCodeGrantTokenCreation(grantInfo)
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

func handleClientCredentialsGrantTokenCreation(context models.GrantInfo) (models.Token, error) {
	if err := validateClientCredentialsGrantRequest(context); err != nil {
		return models.Token{}, err
	}

	return context.TokenModel.GenerateToken(models.TokenContextInfo{
		Subject:  context.AuthenticatedClient.Id,
		ClientId: context.AuthenticatedClient.Id,
		Scopes:   context.Scopes,
	}), nil
}

func validateClientCredentialsGrantRequest(context models.GrantInfo) error {
	if !context.AuthenticatedClient.AreScopesAllowed(context.Scopes) {
		return errors.New("invalid scope")
	}

	return nil
}

//---------------------------------------- Authorization Code ----------------------------------------//

func handleAuthorizationCodeGrantTokenCreation(context models.GrantInfo) (models.Token, error) {
	// TODO
	err := validateAuthorizationCodeGrantRequest(context)
	if err != nil {
		return models.Token{}, err
	}

	return models.Token{}, errors.ErrUnsupported
}

func validateAuthorizationCodeGrantRequest(context models.GrantInfo) error {
	// TODO
	if context.AuthorizationCode == "" {
		return errors.New("the authorization code was not informed")
	}

	return nil
}
