package utils

import (
	"log/slog"
	"strings"

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
		err = issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid grant type",
		}
	}
	if err != nil {
		return models.Token{}, err
	}

	err = ctx.CrudManager.TokenSessionManager.Create(token)
	if err != nil {
		return models.Token{}, err
	}

	return token, nil
}

func getGrantInfo(
	ctx Context,
	request models.TokenRequest,
) (
	models.GrantInfo,
	error,
) {
	// Fetch the authenticated client.
	authenticatedClient, err := getAuthenticatedClient(
		ctx,
		models.ClientAuthnContext{
			ClientId:     request.ClientId,
			ClientSecret: request.ClientSecret,
		},
	)
	if err != nil {
		return models.GrantInfo{}, err
	}

	// Fetch the token model.
	tokenModel, err := ctx.CrudManager.TokenModelManager.Get(authenticatedClient.DefaultTokenModelId)
	if err != nil {
		return models.GrantInfo{}, err
	}

	scopes := []string{}
	if request.Scope != "" {
		scopes = strings.Split(request.Scope, " ")
	}
	return models.GrantInfo{
		GrantType:           request.GrantType,
		AuthenticatedClient: authenticatedClient,
		TokenModel:          tokenModel,
		Scopes:              scopes,
		AuthorizationCode:   request.AuthorizationCode,
		RedirectUri:         request.RedirectUri,
	}, nil
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
	if !grantInfo.AuthenticatedClient.IsGrantTypeAllowed(constants.ClientCredentials) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid grant type",
		}
	}
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
	if grantInfo.AuthorizationCode == "" {
		return models.Token{}, issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid authorization code",
		}
	}

	// Fetch the session using the authorization code.
	session, err := ctx.CrudManager.AuthnSessionManager.GetByAuthorizationCode(grantInfo.AuthorizationCode)
	if err != nil {
		return models.Token{}, issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid authorization code",
		}
	}
	// Always delete the session.
	go ctx.CrudManager.AuthnSessionManager.Delete(session.Id)

	if err := validateAuthorizationCodeGrantRequest(grantInfo, session); err != nil {
		return models.Token{}, err
	}

	return grantInfo.TokenModel.GenerateToken(models.TokenContextInfo{
		Subject:  session.Subject,
		ClientId: session.ClientId,
		Scopes:   session.Scopes,
	}), nil
}

func validateAuthorizationCodeGrantRequest(grantInfo models.GrantInfo, session models.AuthnSession) error {
	if !grantInfo.AuthenticatedClient.IsGrantTypeAllowed(constants.AuthorizationCode) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid grant type",
		}
	}
	if len(grantInfo.Scopes) != 0 || grantInfo.AuthorizationCode == "" || grantInfo.RedirectUri == "" {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid parameter for authorization code",
		}
	}
	if session.ClientId != grantInfo.AuthenticatedClient.Id {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the authorization code was not issued to the client",
		}
	}

	return nil
}

func getAuthenticatedClient(ctx Context, authnContext models.ClientAuthnContext) (models.Client, error) {
	// Fetch the client.
	client, err := ctx.CrudManager.ClientManager.Get(authnContext.ClientId)
	if err != nil {
		ctx.Logger.Info("client not found", slog.String("client_id", authnContext.ClientId))
		return models.Client{}, err
	}

	// Verify that the client is authenticated.
	if !client.Authenticator.IsAuthenticated(authnContext) {
		ctx.Logger.Info("client not authenticated", slog.String("client_id", authnContext.ClientId))
		return models.Client{}, issues.JsonError{
			ErrorCode:        constants.AccessDenied,
			ErrorDescription: "client not authenticated",
		}
	}

	return client, nil
}
