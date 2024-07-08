package par

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func PushAuthorization(
	ctx utils.OAuthContext,
	req utils.PushedAuthorizationRequest,
) (
	requestURI string,
	oauthErr goidc.OAuthError,
) {

	client, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientID), slog.String("error", err.Error()))
		return "", goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "client not authenticated")
	}

	session, oauthErr := initValidAuthnSession(ctx, req, client)
	if oauthErr != nil {
		return "", oauthErr
	}

	requestURI = session.Push(ctx.ParLifetimeSecs)
	if err := ctx.AuthnSessionManager.CreateOrUpdate(ctx, session); err != nil {
		ctx.Logger.Debug("could not create a session")
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}
	return requestURI, nil
}
