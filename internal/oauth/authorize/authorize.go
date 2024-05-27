package authorize

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func InitAuth(ctx utils.Context, req models.AuthorizationRequest) models.OAuthError {
	client, err := getClient(ctx, req)
	if err != nil {
		return err
	}

	if err = initAuth(ctx, client, req); err != nil {
		return redirectError(ctx, err, client)
	}

	return nil
}

func initAuth(ctx utils.Context, client models.Client, req models.AuthorizationRequest) models.OAuthError {
	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}
	return authenticate(ctx, &session)
}

func ContinueAuth(ctx utils.Context, callbackId string) models.OAuthError {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return models.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	if oauthErr := authenticate(ctx, &session); oauthErr != nil {
		client, _ := ctx.ClientManager.Get(session.ClientId) // TODO: handle the error
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func getClient(
	ctx utils.Context,
	req models.AuthorizationRequest,
) (
	models.Client,
	models.OAuthError,
) {
	if req.ClientId == "" {
		return models.Client{}, models.NewOAuthError(constants.InvalidClient, "invalid client_id")
	}

	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return models.Client{}, models.NewOAuthError(constants.InvalidClient, "invalid client_id")
	}

	return client, nil
}
