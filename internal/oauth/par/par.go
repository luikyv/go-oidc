package par

import (
	"log/slog"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/token"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func PushAuthorization(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
) (
	requestUri string,
	oauthErr models.OAuthError,
) {

	client, err := token.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientIdPost))
		return "", models.NewOAuthError(constants.InvalidClient, "client not authenticated")
	}

	session, oauthErr := initValidAuthnSession(ctx, req, client)
	if oauthErr != nil {
		return "", oauthErr
	}
	session.Push(ctx.RequestContext)

	if err := ctx.AuthnSessionManager.CreateOrUpdate(session); err != nil {
		ctx.Logger.Debug("could not create a session")
		return "", models.NewOAuthError(constants.InternalError, err.Error())
	}
	return session.RequestUri, nil
}
