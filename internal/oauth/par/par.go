package par

import (
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

func PushAuthorization(
	ctx *utils.Context,
	req utils.PushedAuthorizationRequest,
) (
	requestURI string,
	oauthErr goidc.OAuthError,
) {

	client, oauthErr := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if oauthErr != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "client not authenticated")
	}

	session, oauthErr := initValidAuthnSession(ctx, req, client)
	if oauthErr != nil {
		return "", oauthErr
	}

	requestURI, err := session.Push(ctx.ParLifetimeSecs)
	if err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	if err := ctx.CreateOrUpdateAuthnSession(session); err != nil {
		return "", goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}
	return requestURI, nil
}
